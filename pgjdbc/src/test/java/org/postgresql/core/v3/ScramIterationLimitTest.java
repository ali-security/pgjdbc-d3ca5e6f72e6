/*
 * Copyright (c) 2025, PostgreSQL Global Development Group
 * See the LICENSE file in the project root for more information.
 */

package org.postgresql.core.v3;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.postgresql.PGProperty;
import org.postgresql.core.PGStream;
import org.postgresql.util.HostSpec;
import org.postgresql.util.PSQLException;
import org.postgresql.util.PSQLState;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Base64;
import java.util.Properties;

import javax.net.SocketFactory;

/**
 * Exploit-style regression test for the SCRAM PBKDF2 iteration-count denial of service
 * (CVE-2026-42198).
 *
 * <p>A malicious or compromised server can answer the client-first-message with an
 * arbitrarily large {@code i=} (iteration count) in the server-first-message. Without a
 * client-side ceiling the driver happily runs PBKDF2 for that many rounds, burning CPU on an
 * attacker-controlled work factor before authentication can even fail.</p>
 *
 * <p>The test plays the role of the hostile server over a plain loopback socket: it advertises
 * SCRAM-SHA-256, reads the real client-first-message produced by
 * {@link ScramAuthenticator#handleAuthenticationSASL()} and forges a server-first-message whose
 * nonce correctly extends the client nonce (otherwise the SCRAM library would reject the message
 * before the iteration count is ever looked at, and the test would pass for the wrong reason).
 * Every rejection case is paired with a case that pushes the very same forgery past the guard,
 * which proves the forged message is well formed.</p>
 */
class ScramIterationLimitTest {

  private static final char[] PASSWORD = "s3cr3t".toCharArray();

  /** Valid base64, so PBKDF2 really does run whenever the guard lets the message through. */
  private static final String SALT = Base64.getEncoder().encodeToString(
      new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});

  private static final String SERVER_NONCE_SUFFIX = "3rfcNHYJY1ZVvWVs7j";

  private static final int SOCKET_TIMEOUT_MS = 30000;

  /** The iteration count a hostile server would use to pin the client's CPU. */
  private static final int HOSTILE_ITERATIONS = 100_000_000;

  private ServerSocket serverSocket;
  private Socket peer;
  private PGStream pgStream;
  private DataInputStream serverIn;
  private OutputStream serverOut;

  @BeforeEach
  void setUp() throws IOException {
    serverSocket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
  }

  @AfterEach
  void tearDown() {
    closeQuietly(pgStream);
    closeQuietly(peer);
    closeQuietly(serverSocket);
  }

  /**
   * The attack: the server demands 100 million PBKDF2 rounds. The driver must refuse before the
   * key derivation runs, so the call returns promptly instead of pinning a CPU core.
   */
  @Test
  void hostileIterationCountIsRejectedBeforePbkdf2Runs() {
    long start = System.nanoTime();
    PSQLException e = assertThrows(PSQLException.class,
        () -> performHandshake(new Properties(), HOSTILE_ITERATIONS));
    long elapsedMs = (System.nanoTime() - start) / 1000000L;

    assertIterationLimitFailure(e);
    // Secondary signal only; the message assertion above is the primary proof. With the guard in
    // place the handshake returns in well under a second, and with the guard removed the PBKDF2
    // derivation for HOSTILE_ITERATIONS was measured at ~27s. 20s therefore stays comfortably
    // below the unguarded cost while leaving plenty of headroom for a loaded CI machine.
    assertTrue(elapsedMs < 20000,
        "Rejection must happen before the PBKDF2 derivation, but the handshake took "
            + elapsedMs + "ms");
  }

  /**
   * Same forgery, only the configured ceiling changes: one round above the limit is refused,
   * exactly at the limit is accepted. The accepted case proves the forged server-first-message is
   * well formed and reaches the PBKDF2 step.
   */
  @Test
  void iterationCountAboveConfiguredLimitIsRejected() {
    Properties above = new Properties();
    PGProperty.SCRAM_MAX_ITERATIONS.set(above, 4096);
    assertIterationLimitFailure(assertThrows(PSQLException.class,
        () -> performHandshake(above, 4097)));
  }

  @Test
  void iterationCountAtConfiguredLimitIsAccepted() throws Exception {
    Properties atLimit = new Properties();
    PGProperty.SCRAM_MAX_ITERATIONS.set(atLimit, 4096);
    assertDoesNotThrow(() -> performHandshake(atLimit, 4096));
  }

  /**
   * The default ceiling (100000) must be in force even when the property is never set — that is
   * what protects an unmodified application.
   */
  @Test
  void defaultLimitRejectsIterationCountAboveOneHundredThousand() {
    assertEquals("100000", PGProperty.SCRAM_MAX_ITERATIONS.getDefaultValue());
    assertIterationLimitFailure(assertThrows(PSQLException.class,
        () -> performHandshake(new Properties(), 100001)));
  }

  @Test
  void defaultLimitAcceptsIterationCountAtOneHundredThousand() {
    assertDoesNotThrow(() -> performHandshake(new Properties(), 100000));
  }

  /**
   * A value of zero opts out of the check, so the very forgery rejected above now goes through.
   * A moderate iteration count keeps the PBKDF2 run cheap.
   */
  @Test
  void zeroDisablesTheCheck() {
    Properties disabled = new Properties();
    PGProperty.SCRAM_MAX_ITERATIONS.set(disabled, 0);
    assertDoesNotThrow(() -> performHandshake(disabled, 4097));
  }

  /**
   * A negative ceiling would silently disable the guard, so it is rejected as a configuration
   * error instead.
   */
  @Test
  void negativeLimitIsRejectedAsInvalidParameter() throws Exception {
    Properties negative = new Properties();
    PGProperty.SCRAM_MAX_ITERATIONS.set(negative, -1);

    PSQLException fromFactoryPath = assertThrows(PSQLException.class,
        () -> ScramAuthenticator.maxIterations(negative));
    assertEquals(PSQLState.INVALID_PARAMETER_VALUE.getState(), fromFactoryPath.getSQLState());
    assertTrue(fromFactoryPath.getMessage().contains("must be a non-negative integer"),
        "Unexpected message: " + fromFactoryPath.getMessage());

    PSQLException fromConstructor = assertThrows(PSQLException.class,
        () -> performHandshake(negative, 4096));
    assertEquals(PSQLState.INVALID_PARAMETER_VALUE.getState(), fromConstructor.getSQLState());
    assertTrue(fromConstructor.getMessage().contains("must be a non-negative integer"),
        "Unexpected message: " + fromConstructor.getMessage());
  }

  @Test
  void nonNumericLimitIsRejectedAsInvalidParameter() {
    Properties bogus = new Properties();
    PGProperty.SCRAM_MAX_ITERATIONS.set(bogus, "not-a-number");

    PSQLException e = assertThrows(PSQLException.class,
        () -> ScramAuthenticator.maxIterations(bogus));
    assertEquals(PSQLState.INVALID_PARAMETER_VALUE.getState(), e.getSQLState());
  }

  /**
   * A malformed iteration count must fail as a protocol error, not with an unrelated exception
   * leaking out of the new guard.
   */
  @Test
  void nonNumericIterationCountIsRejectedCleanly() throws Exception {
    assertMalformedServerFirstMessage(",i=notanumber");
  }

  /**
   * Same for a server-first-message that carries no iteration attribute at all.
   */
  @Test
  void missingIterationAttributeIsRejectedCleanly() throws Exception {
    assertMalformedServerFirstMessage(",z=1");
  }

  private void assertMalformedServerFirstMessage(String iterationAttribute) throws Exception {
    ScramAuthenticator authenticator = openSession(new Properties());
    authenticator.handleAuthenticationSASL();
    String clientNonce = readClientNonce();

    PSQLException e = assertThrows(PSQLException.class,
        () -> sendServerFirstMessage(authenticator,
            "r=" + clientNonce + SERVER_NONCE_SUFFIX + ",s=" + SALT + iterationAttribute));
    assertEquals(PSQLState.CONNECTION_REJECTED.getState(), e.getSQLState());
    assertTrue(e.getMessage().startsWith("SCRAM authentication failed"),
        "Unexpected message: " + e.getMessage());
  }

  private static void assertIterationLimitFailure(PSQLException e) {
    // The malformed-message path throws the same type and SQL state, so the message text is what
    // actually proves the iteration guard fired.
    assertTrue(e.getMessage().contains("exceeds the client-side limit"),
        "Expected the SCRAM iteration limit to reject the handshake, but got: " + e.getMessage());
    assertEquals(PSQLState.CONNECTION_REJECTED.getState(), e.getSQLState());
  }

  /**
   * Drives a full client-side SCRAM exchange against the forged server, stopping right after the
   * server-first-message is processed.
   */
  private void performHandshake(Properties info, int iterations) throws Exception {
    ScramAuthenticator authenticator = openSession(info);
    authenticator.handleAuthenticationSASL();
    String clientNonce = readClientNonce();
    sendServerFirstMessage(authenticator,
        "r=" + clientNonce + SERVER_NONCE_SUFFIX + ",s=" + SALT + ",i=" + iterations);
  }

  private ScramAuthenticator openSession(Properties info) throws Exception {
    HostSpec hostSpec = new HostSpec(
        serverSocket.getInetAddress().getHostAddress(), serverSocket.getLocalPort());
    pgStream = new PGStream(SocketFactory.getDefault(), hostSpec, SOCKET_TIMEOUT_MS, 8192);
    pgStream.getSocket().setSoTimeout(SOCKET_TIMEOUT_MS);
    peer = serverSocket.accept();
    peer.setSoTimeout(SOCKET_TIMEOUT_MS);
    serverIn = new DataInputStream(peer.getInputStream());
    serverOut = peer.getOutputStream();

    // Body of an AuthenticationSASL message: the NUL terminated mechanism list.
    serverOut.write("SCRAM-SHA-256".getBytes(UTF_8));
    serverOut.write(0);
    serverOut.write(0);
    serverOut.flush();

    return new ScramAuthenticator(PASSWORD.clone(), pgStream, info);
  }

  /**
   * Reads the SASLInitialResponse the driver just sent and returns the client nonce, so the forged
   * server-first-message can extend it as RFC 5802 requires.
   */
  private String readClientNonce() throws IOException {
    assertEquals('p', serverIn.read(), "Expected a SASLInitialResponse message");
    serverIn.readInt(); // message length
    ByteArrayOutputStream mechanism = new ByteArrayOutputStream();
    int b;
    while ((b = serverIn.read()) > 0) {
      mechanism.write(b);
    }
    assertEquals("SCRAM-SHA-256", new String(mechanism.toByteArray(), UTF_8));

    byte[] body = new byte[serverIn.readInt()];
    serverIn.readFully(body);
    String clientFirstMessage = new String(body, UTF_8);
    int nonceIndex = clientFirstMessage.lastIndexOf(",r=");
    assertTrue(nonceIndex >= 0,
        "client-first-message should carry a nonce: " + clientFirstMessage);
    return clientFirstMessage.substring(nonceIndex + 3);
  }

  private void sendServerFirstMessage(ScramAuthenticator authenticator, String serverFirstMessage)
      throws IOException, PSQLException {
    byte[] bytes = serverFirstMessage.getBytes(UTF_8);
    serverOut.write(bytes);
    serverOut.flush();
    authenticator.handleAuthenticationSASLContinue(bytes.length);
  }

  private static void closeQuietly(Closeable closeable) {
    if (closeable != null) {
      try {
        closeable.close();
      } catch (IOException ignored) {
        // nothing useful to do while tearing the fixture down
      }
    }
  }
}
