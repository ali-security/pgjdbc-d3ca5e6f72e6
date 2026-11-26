/*
 * Copyright (c) 2026, PostgreSQL Global Development Group
 * See the LICENSE file in the project root for more information.
 */

package org.postgresql.core.v3;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.postgresql.Driver;
import org.postgresql.PGProperty;
import org.postgresql.util.PSQLState;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.sql.SQLException;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A NUL inside a startup parameter would terminate the value early inside the startup packet,
 * letting the remainder be read by the server as further (overriding) parameters. The driver
 * must refuse such values before anything is written to the server.
 */
class StartupParamNulTest {

  private ServerSocket server;
  private Thread acceptor;
  private final AtomicInteger bytesReceived = new AtomicInteger(-1);

  @BeforeEach
  void startFakeServer() throws IOException {
    server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
    acceptor = new Thread(() -> {
      try (Socket s = server.accept()) {
        s.setSoTimeout(5000);
        InputStream in = s.getInputStream();
        int total = 0;
        byte[] buf = new byte[8192];
        try {
          int n;
          // Read the startup packet length (or EOF when the client gives up first)
          while (total < 4 && (n = in.read(buf)) > 0) {
            total += n;
          }
        } catch (IOException ignore) {
          // timeout or reset: report what was read
        }
        bytesReceived.set(total);
      } catch (IOException ignore) {
        // server closed
      }
    }, "StartupParamNulTest-server");
    acceptor.setDaemon(true);
    acceptor.start();
  }

  @AfterEach
  void stopFakeServer() throws Exception {
    server.close();
    acceptor.join(10000);
  }

  private SQLException connect(String property, String value) throws InterruptedException {
    Properties props = new Properties();
    PGProperty.USER.set(props, "test");
    PGProperty.PASSWORD.set(props, "test");
    PGProperty.SSL_MODE.set(props, "disable");
    PGProperty.GSS_ENC_MODE.set(props, "disable");
    PGProperty.CONNECT_TIMEOUT.set(props, 5);
    PGProperty.SOCKET_TIMEOUT.set(props, 5);
    props.setProperty(property, value);
    String url = "jdbc:postgresql://" + server.getInetAddress().getHostAddress() + ":"
        + server.getLocalPort() + "/test";
    SQLException e = assertThrows(SQLException.class, () -> new Driver().connect(url, props));
    acceptor.join(10000);
    return e;
  }

  @ParameterizedTest
  @ValueSource(strings = {"options", "ApplicationName", "user", "currentSchema"})
  void nulInStartupParameterIsRejected(String property) throws Exception {
    SQLException e = connect(property, "x\u0000replication\u0000database");
    assertEquals(PSQLState.INVALID_PARAMETER_VALUE.getState(), e.getSQLState(), e.toString());
    assertTrue(e.getMessage().contains("NUL"), e.getMessage());
    assertEquals(0, bytesReceived.get(), "no startup packet must reach the server");
  }

  @ParameterizedTest
  @ValueSource(strings = {"options", "ApplicationName"})
  void valueWithoutNulIsSent(String property) throws Exception {
    SQLException e = connect(property, "plain-value");
    assertNotEquals(PSQLState.INVALID_PARAMETER_VALUE.getState(), e.getSQLState(), e.toString());
    assertTrue(bytesReceived.get() >= 4, "startup packet should be sent");
  }
}
