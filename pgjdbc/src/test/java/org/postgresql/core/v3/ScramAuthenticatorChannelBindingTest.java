/*
 * Copyright (c) 2026, PostgreSQL Global Development Group
 * See the LICENSE file in the project root for more information.
 */

package org.postgresql.core.v3;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Properties;
import java.util.Set;

import javax.net.SocketFactory;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/**
 * Exploit-style regression test for the {@code channelBinding=require} downgrade
 * (GHSA-j92g-9f8w-j867).
 *
 * <p>A user asking for {@code channelBinding=require} expects the connection to fail unless
 * channel binding is actually in force. The driver used to hand whatever channel binding data it
 * could extract to the SCRAM library and then trust the library's mechanism choice. When no
 * binding data could be derived - for instance because the server certificate is signed with
 * Ed25519, which has no {@code tls-server-end-point} hash under RFC 5929 - the library quietly
 * picked the plain {@code SCRAM-SHA-256} mechanism out of the advertised list even though the
 * server also offered {@code SCRAM-SHA-256-PLUS}. The connection then came up with no channel
 * binding at all, so a man-in-the-middle holding a certificate the client happens to accept is
 * no longer detected, and the caller had no way of knowing.</p>
 *
 * <p>The test plays the role of that server: a plain loopback socket carries the protocol while a
 * hand-written {@link SSLSocket} stub supplies the TLS session details the driver inspects (no
 * mocking framework is on the test classpath). Every rejection is paired with the very same
 * exchange under {@code channelBinding=prefer}, which still completes and still negotiates the
 * non-PLUS mechanism - that control case is the downgrade itself, and it proves the rejection
 * comes from the {@code require} guard rather than from a broken fixture.</p>
 */
class ScramAuthenticatorChannelBindingTest {

  private static final char[] PASSWORD = "s3cr3t".toCharArray();

  private static final int SOCKET_TIMEOUT_MS = 30000;

  /**
   * A signature algorithm with no associated hash for RFC 5929 {@code tls-server-end-point}, so no
   * channel binding data can be derived from a certificate signed with it. The algorithm name is
   * stubbed rather than taken from a parsed certificate because the JDK reports it as the OID
   * {@code 1.3.101.112} on some releases and as {@code Ed25519} on others.
   */
  private static final String NO_HASH_SIGNATURE_ALGORITHM = "Ed25519";

  /** The server offers channel binding, so a compliant client must use it. */
  private static final String[] PLUS_AND_PLAIN =
      {"SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"};

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
   * The attack: the peer certificate carries a signature algorithm with no
   * {@code tls-server-end-point} hash, so the driver cannot compute channel binding data. Under
   * {@code require} it must refuse the connection instead of continuing without channel binding.
   * Both Edwards-curve algorithms named by the advisory are covered.
   */
  @ParameterizedTest
  @ValueSource(strings = {"Ed25519", "Ed448"})
  void requireRejectsCertificateWithoutChannelBindingHash(String signatureAlgorithm) {
    PSQLException e = assertThrows(PSQLException.class,
        () -> openSession(channelBinding("require"),
            new Certificate[]{new StubX509Certificate(signatureAlgorithm)},
            PLUS_AND_PLAIN));

    assertEquals(PSQLState.CONNECTION_REJECTED.getState(), e.getSQLState());
    // Every other require failure throws the same type and SQL state, so the message text is what
    // proves this particular guard fired. It also names the offending algorithm for the operator.
    assertTrue(e.getMessage().contains(signatureAlgorithm),
        "The failure must name the signature algorithm, but was: " + e.getMessage());
    assertTrue(e.getMessage().contains("tls-server-end-point"),
        "Expected the certificate signature algorithm guard, but was: " + e.getMessage());
  }

  /**
   * Control case for the test above, and a demonstration of the downgrade it prevents: the exact
   * same certificate under {@code prefer} still connects, and the mechanism the driver puts on the
   * wire is the non-PLUS one. That is acceptable for {@code prefer} and must never happen for
   * {@code require}.
   */
  @Test
  void preferSilentlyFallsBackForCertificateWithoutChannelBindingHash() throws Exception {
    ScramAuthenticator authenticator =
        openSession(channelBinding("prefer"),
            new Certificate[]{new StubX509Certificate(NO_HASH_SIGNATURE_ALGORITHM)},
            PLUS_AND_PLAIN);

    assertNotNull(authenticator);
    assertEquals("SCRAM-SHA-256", negotiatedMechanism(authenticator));
  }

  /**
   * The second half of the guard. When the TLS session exposes no X.509 peer certificate at all
   * the driver has no binding data either, and the SCRAM library happily selects the advertised
   * non-PLUS mechanism. Under {@code require} the negotiated mechanism must be rejected because it
   * does not use channel binding.
   */
  @Test
  void requireRejectsNegotiatedMechanismWithoutChannelBinding() {
    PSQLException e = assertThrows(PSQLException.class,
        () -> openSession(channelBinding("require"),
            new Certificate[]{new StubNonX509Certificate()},
            PLUS_AND_PLAIN));

    assertEquals(PSQLState.CONNECTION_REJECTED.getState(), e.getSQLState());
    assertTrue(e.getMessage().contains("does not use channel binding"),
        "Expected the negotiated mechanism guard, but was: " + e.getMessage());
    assertTrue(e.getMessage().contains("SCRAM-SHA-256"),
        "The failure must name the negotiated mechanism, but was: " + e.getMessage());
  }

  /**
   * Control case for the test above: with the same session, {@code prefer} connects and downgrades
   * to the non-PLUS mechanism, which is what {@code require} now refuses.
   */
  @Test
  void preferSilentlyFallsBackWhenPeerCertificateIsNotX509() throws Exception {
    ScramAuthenticator authenticator =
        openSession(channelBinding("prefer"),
            new Certificate[]{new StubNonX509Certificate()},
            PLUS_AND_PLAIN);

    assertNotNull(authenticator);
    assertEquals("SCRAM-SHA-256", negotiatedMechanism(authenticator));
  }

  /**
   * A certificate the driver can derive binding data from keeps working: {@code require}
   * negotiates the PLUS mechanism. Without this case the two rejections above could be satisfied
   * by refusing every {@code require} connection.
   */
  @Test
  void requireAcceptsCertificateWithChannelBindingHash() throws Exception {
    ScramAuthenticator authenticator =
        openSession(channelBinding("require"),
            new Certificate[]{new StubX509Certificate("SHA256withRSA")},
            PLUS_AND_PLAIN);

    assertNotNull(authenticator);
    assertEquals("SCRAM-SHA-256-PLUS", negotiatedMechanism(authenticator));
  }

  private static Properties channelBinding(String value) {
    Properties info = new Properties();
    PGProperty.CHANNEL_BINDING.set(info, value);
    return info;
  }

  /**
   * Connects a real {@link PGStream} to the loopback server, swaps in a TLS socket stub the way
   * {@code MakeSSL} does for a real connection, advertises {@code mechanisms} and lets the driver
   * negotiate.
   */
  private ScramAuthenticator openSession(Properties info, Certificate[] peerCertificates,
      String... mechanisms) throws Exception {
    HostSpec hostSpec = new HostSpec(
        serverSocket.getInetAddress().getHostAddress(), serverSocket.getLocalPort());
    pgStream = new PGStream(SocketFactory.getDefault(), hostSpec, SOCKET_TIMEOUT_MS, 8192);
    pgStream.getSocket().setSoTimeout(SOCKET_TIMEOUT_MS);
    peer = serverSocket.accept();
    peer.setSoTimeout(SOCKET_TIMEOUT_MS);
    serverIn = new DataInputStream(peer.getInputStream());
    serverOut = peer.getOutputStream();

    // Body of an AuthenticationSASL message: the NUL terminated mechanism list.
    for (String mechanism : mechanisms) {
      serverOut.write(mechanism.getBytes(UTF_8));
      serverOut.write(0);
    }
    serverOut.write(0);
    serverOut.flush();

    // The driver replaces the plain socket with the TLS one before authenticating, so the SCRAM
    // code sees an SSLSocket while the protocol still flows over the loopback connection.
    pgStream.changeSocket(new StubSslSocket(pgStream.getSocket(), peerCertificates));

    return new ScramAuthenticator(PASSWORD.clone(), pgStream, info);
  }

  /**
   * Sends the client-first-message and reports the mechanism name the driver put on the wire,
   * which is the mechanism it really negotiated.
   */
  private String negotiatedMechanism(ScramAuthenticator authenticator) throws IOException {
    authenticator.handleAuthenticationSASL();
    assertEquals('p', serverIn.read(), "Expected a SASLInitialResponse message");
    serverIn.readInt(); // message length
    ByteArrayOutputStream mechanism = new ByteArrayOutputStream();
    int b;
    while ((b = serverIn.read()) > 0) {
      mechanism.write(b);
    }
    return new String(mechanism.toByteArray(), UTF_8);
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

  /**
   * An {@link SSLSocket} that carries no TLS at all: the byte stream is delegated to the already
   * connected loopback socket, and only the handful of accessors the driver's channel binding code
   * touches are implemented.
   */
  private static class StubSslSocket extends SSLSocket {
    private final Socket delegate;
    private final SSLSession session;

    StubSslSocket(Socket delegate, Certificate[] peerCertificates) {
      this.delegate = delegate;
      this.session = stubSession(peerCertificates);
    }

    /**
     * {@link SSLSession} is an interface whose method set differs between JDK releases, so it is
     * implemented reflectively instead of being subclassed.
     */
    private static SSLSession stubSession(Certificate[] peerCertificates) {
      InvocationHandler handler = new InvocationHandler() {
        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
          String name = method.getName();
          if ("getPeerCertificates".equals(name)) {
            return peerCertificates.clone();
          }
          if ("toString".equals(name)) {
            return "StubSSLSession";
          }
          if ("hashCode".equals(name)) {
            return System.identityHashCode(proxy);
          }
          if ("equals".equals(name)) {
            return proxy == args[0];
          }
          throw new UnsupportedOperationException(name);
        }
      };
      return (SSLSession) Proxy.newProxyInstance(
          ScramAuthenticatorChannelBindingTest.class.getClassLoader(),
          new Class<?>[]{SSLSession.class},
          handler);
    }

    @Override
    public SSLSession getSession() {
      return session;
    }

    @Override
    public InputStream getInputStream() throws IOException {
      return delegate.getInputStream();
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
      return delegate.getOutputStream();
    }

    @Override
    public void setTcpNoDelay(boolean on) throws SocketException {
      delegate.setTcpNoDelay(on);
    }

    @Override
    public boolean getTcpNoDelay() throws SocketException {
      return delegate.getTcpNoDelay();
    }

    @Override
    public int getSendBufferSize() throws SocketException {
      return delegate.getSendBufferSize();
    }

    @Override
    public int getReceiveBufferSize() throws SocketException {
      return delegate.getReceiveBufferSize();
    }

    @Override
    public void setSoTimeout(int timeout) throws SocketException {
      delegate.setSoTimeout(timeout);
    }

    @Override
    public int getSoTimeout() throws SocketException {
      return delegate.getSoTimeout();
    }

    @Override
    public boolean isConnected() {
      return delegate.isConnected();
    }

    @Override
    public boolean isClosed() {
      return delegate.isClosed();
    }

    @Override
    public InetAddress getInetAddress() {
      return delegate.getInetAddress();
    }

    @Override
    public int getPort() {
      return delegate.getPort();
    }

    @Override
    public void close() throws IOException {
      delegate.close();
    }

    @Override
    public String[] getSupportedCipherSuites() {
      throw new UnsupportedOperationException();
    }

    @Override
    public String[] getEnabledCipherSuites() {
      throw new UnsupportedOperationException();
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
      throw new UnsupportedOperationException();
    }

    @Override
    public String[] getSupportedProtocols() {
      throw new UnsupportedOperationException();
    }

    @Override
    public String[] getEnabledProtocols() {
      throw new UnsupportedOperationException();
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void startHandshake() {
      throw new UnsupportedOperationException();
    }

    @Override
    public void setUseClientMode(boolean mode) {
      throw new UnsupportedOperationException();
    }

    @Override
    public boolean getUseClientMode() {
      return true;
    }

    @Override
    public void setNeedClientAuth(boolean need) {
      throw new UnsupportedOperationException();
    }

    @Override
    public boolean getNeedClientAuth() {
      return false;
    }

    @Override
    public void setWantClientAuth(boolean want) {
      throw new UnsupportedOperationException();
    }

    @Override
    public boolean getWantClientAuth() {
      return false;
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
      throw new UnsupportedOperationException();
    }

    @Override
    public boolean getEnableSessionCreation() {
      return true;
    }
  }

  /**
   * A peer certificate whose only interesting property is the signature algorithm the channel
   * binding hash is derived from.
   */
  private static class StubX509Certificate extends X509Certificate {
    private static final long serialVersionUID = 1L;

    private final String sigAlgName;

    StubX509Certificate(String sigAlgName) {
      this.sigAlgName = sigAlgName;
    }

    @Override
    public String getSigAlgName() {
      return sigAlgName;
    }

    @Override
    public byte[] getEncoded() {
      // Stands in for the DER encoding the channel binding hash is computed over.
      return new byte[]{0x30, 0x03, 0x02, 0x01, 0x01};
    }

    @Override
    public void checkValidity() {
    }

    @Override
    public void checkValidity(Date date) {
    }

    @Override
    public int getVersion() {
      return 3;
    }

    @Override
    public BigInteger getSerialNumber() {
      return BigInteger.ONE;
    }

    @Override
    public Principal getIssuerDN() {
      throw new UnsupportedOperationException();
    }

    @Override
    public Principal getSubjectDN() {
      throw new UnsupportedOperationException();
    }

    @Override
    public Date getNotBefore() {
      return new Date(0L);
    }

    @Override
    public Date getNotAfter() {
      return new Date(Long.MAX_VALUE);
    }

    @Override
    public byte[] getTBSCertificate() {
      throw new UnsupportedOperationException();
    }

    @Override
    public byte[] getSignature() {
      throw new UnsupportedOperationException();
    }

    @Override
    public String getSigAlgOID() {
      throw new UnsupportedOperationException();
    }

    @Override
    public byte[] getSigAlgParams() {
      throw new UnsupportedOperationException();
    }

    @Override
    public boolean[] getIssuerUniqueID() {
      throw new UnsupportedOperationException();
    }

    @Override
    public boolean[] getSubjectUniqueID() {
      throw new UnsupportedOperationException();
    }

    @Override
    public boolean[] getKeyUsage() {
      throw new UnsupportedOperationException();
    }

    @Override
    public int getBasicConstraints() {
      return -1;
    }

    @Override
    public void verify(PublicKey key) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void verify(PublicKey key, String sigProvider) {
      throw new UnsupportedOperationException();
    }

    @Override
    public String toString() {
      return "StubX509Certificate[" + sigAlgName + "]";
    }

    @Override
    public PublicKey getPublicKey() {
      throw new UnsupportedOperationException();
    }

    @Override
    public boolean hasUnsupportedCriticalExtension() {
      return false;
    }

    @Override
    public Set<String> getCriticalExtensionOIDs() {
      return null;
    }

    @Override
    public Set<String> getNonCriticalExtensionOIDs() {
      return null;
    }

    @Override
    public byte[] getExtensionValue(String oid) {
      return null;
    }
  }

  /**
   * A peer certificate that is not an X.509 one, so the driver cannot derive channel binding data
   * from it at all.
   */
  private static class StubNonX509Certificate extends Certificate {
    private static final long serialVersionUID = 1L;

    StubNonX509Certificate() {
      super("Stub");
    }

    @Override
    public byte[] getEncoded() {
      return new byte[0];
    }

    @Override
    public void verify(PublicKey key) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void verify(PublicKey key, String sigProvider) {
      throw new UnsupportedOperationException();
    }

    @Override
    public String toString() {
      return "StubNonX509Certificate";
    }

    @Override
    public PublicKey getPublicKey() {
      throw new UnsupportedOperationException();
    }
  }
}
