/*
 * Copyright (c) 2026, PostgreSQL Global Development Group
 * See the LICENSE file in the project root for more information.
 */

package org.postgresql.test.jdbc2;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import org.postgresql.PGProperty;
import org.postgresql.jdbc.PreferQueryMode;
import org.postgresql.test.TestUtil;
import org.postgresql.test.util.BrokenInputStream;
import org.postgresql.util.PSQLState;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * A parameter value that fails while the driver sends it must leave the connection either in sync
 * with the backend or closed. A connection that stays open with part of a message in its send
 * buffer makes the backend read the next request as the rest of that message, so bytes of a value
 * sent later would be read as protocol messages.
 */
public class BrokenBinaryStreamStateTest {
  private static final String TABLE = "broken_binary_stream_state";
  private static final String SMUGGLED_TABLE = "broken_binary_stream_smuggled";
  private static final int DECLARED_LENGTH = 2;
  private static final int STREAM_LENGTH = 1000;
  /**
   * Larger than the in-memory limit of a value without a length, so the value is spooled to a
   * temporary file, which is released after the first Bind.
   */
  private static final int SPOOLED_LENGTH = 65536;
  /**
   * Parse of {@code SELECT $1} with one parameter type: type, length, name, query, type count,
   * one type.
   */
  private static final int PARSE_SELECT_PARAM_LENGTH = 1 + 4 + 1 + "SELECT $1".length() + 1 + 2 + 4;
  /**
   * Bind of an unnamed statement to an unnamed portal with one binary parameter, up to the value:
   * type, length, portal, statement, format count, format, value count, value length.
   */
  private static final int BIND_HEADER_LENGTH = 1 + 4 + 1 + 1 + 2 + 2 + 2 + 4;
  private static final long ATTACKED_BACKEND_LOCK = 4_244_134_843L;

  enum Shape {
    SINGLE,
    BATCH_LAST_ENTRY_FAILS,
    BATCH_FIRST_ENTRY_FAILS,
  }

  enum Failure {
    READ_THROWS,
    SHORTER_THAN_DECLARED,
  }

  @BeforeAll
  static void createTable() throws SQLException {
    try (Connection conn = TestUtil.openDB()) {
      TestUtil.createTable(conn, TABLE, "b bytea");
    }
  }

  @AfterAll
  static void dropTable() throws SQLException {
    try (Connection conn = TestUtil.openDB()) {
      TestUtil.dropTable(conn, TABLE);
      TestUtil.dropTable(conn, SMUGGLED_TABLE);
    }
  }

  @BeforeEach
  void emptyTable() throws SQLException {
    try (Connection conn = TestUtil.openDB()) {
      TestUtil.execute(conn, "DELETE FROM " + TABLE);
      TestUtil.dropTable(conn, SMUGGLED_TABLE);
    }
  }

  static List<Arguments> cases() {
    List<Arguments> cases = new ArrayList<>();
    for (PreferQueryMode mode : new PreferQueryMode[]{PreferQueryMode.SIMPLE,
        PreferQueryMode.EXTENDED}) {
      for (boolean autoCommit : new boolean[]{true, false}) {
        for (Shape shape : Shape.values()) {
          for (Failure failure : Failure.values()) {
            cases.add(Arguments.of(mode, autoCommit, shape, failure));
          }
        }
      }
    }
    return cases;
  }

  @ParameterizedTest(name = "{0}, autoCommit={1}, {2}, {3}")
  @MethodSource("cases")
  void connectionIsUsableOrClosedAfterBrokenStream(PreferQueryMode mode, boolean autoCommit,
      Shape shape, Failure failure) throws SQLException {
    Properties props = new Properties();
    PGProperty.PREFER_QUERY_MODE.set(props, mode.value());
    try (Connection conn = TestUtil.openDB(props)) {
      conn.setAutoCommit(autoCommit);
      assertThrows(SQLException.class, () -> insert(conn, shape, failure),
          "a stream that breaks while the driver sends it must fail the statement");
      if (shape == Shape.SINGLE) {
        assertFalse(conn.isClosed(),
            "a single statement that fails to bind must not close the connection");
      }
      if (!conn.isClosed()) {
        assertConnectionAnswersItsOwnQuery(conn);
      }
    }
  }

  /**
   * A {@code setBinaryStream()} value without a length is spooled to a temporary file, which is
   * released after the first Bind. Running the statement again must not leave the header of a
   * Bind in the send buffer, or the backend reads the next value as messages.
   */
  @Test
  void releasedStreamValueCannotSmuggleQuery() throws SQLException {
    byte[] smuggled = smuggledQuery(SPOOLED_LENGTH);
    Throwable rerunFailure;
    byte[] echoed = null;
    SQLException sendFailure = null;
    try (Connection conn = openAttackedConnection();
         PreparedStatement ps = conn.prepareStatement("SELECT length(?)")) {
      ps.setBinaryStream(1, new ByteArrayInputStream(new byte[SPOOLED_LENGTH]));
      try (ResultSet rs = ps.executeQuery()) {
        assertTrue(rs.next());
        assertEquals(SPOOLED_LENGTH, rs.getInt(1));
      }
      rerunFailure = assertThrows(Throwable.class, ps::executeQuery,
          "the released value can't be sent again");
      try {
        echoed = selectValue(conn, smuggled);
      } catch (SQLException e) {
        sendFailure = e;
      }
    }
    assertSmuggledQueryDidNotRun();
    assertInstanceOf(SQLException.class, rerunFailure,
        "a released value must be reported as a failed Bind");
    assertEquals(PSQLState.INVALID_PARAMETER_VALUE.getState(),
        ((SQLException) rerunFailure).getSQLState(),
        "a released value must be reported as a failed Bind");
    if (sendFailure != null) {
      fail("the connection must stay usable after a failed Bind", sendFailure);
    }
    assertArrayEquals(smuggled, echoed, "the backend must read the value as data");
  }

  /**
   * An unchecked exception from the source of a value interrupts the Bind after its header is
   * buffered, so the driver must close the connection.
   */
  @Test
  void uncheckedStreamFailureCannotSmuggleQuery() throws SQLException {
    byte[] smuggled = smuggledQuery(STREAM_LENGTH);
    boolean closed;
    SQLException sendFailure = null;
    try (Connection conn = openAttackedConnection();
         PreparedStatement ps = conn.prepareStatement("SELECT length(?)")) {
      ps.setBinaryStream(1, new InputStream() {
        @Override
        public int read() {
          throw new IllegalStateException("The source of the value failed");
        }
      }, STREAM_LENGTH);
      assertThrows(IllegalStateException.class, ps::executeQuery,
          "the exception from the source of the value must reach the caller");
      closed = conn.isClosed();
      try {
        selectValue(conn, smuggled);
      } catch (SQLException e) {
        sendFailure = e;
      }
    }
    assertSmuggledQueryDidNotRun();
    assertTrue(closed,
        "an unchecked exception that interrupts a request must close the connection");
    assertNotNull(sendFailure, "a closed connection must refuse the next statement");
    assertEquals(PSQLState.CONNECTION_DOES_NOT_EXIST.getState(), sendFailure.getSQLState());
  }

  /**
   * The driver runs a statement again after "cached plan must not change result type". The value
   * of the stream parameter is released by then, so the second Bind must fail cleanly.
   */
  @Test
  void retryAfterCachedPlanChangeReportsReleasedStream() throws SQLException {
    Properties props = new Properties();
    PGProperty.PREFER_QUERY_MODE.set(props, PreferQueryMode.EXTENDED.value());
    PGProperty.PREPARE_THRESHOLD.set(props, 1);
    try (Connection conn = TestUtil.openDB(props)) {
      TestUtil.createTempTable(conn, "broken_binary_stream_plan", "a int");
      try (PreparedStatement ps = conn.prepareStatement(
          "SELECT * FROM broken_binary_stream_plan WHERE length(?) > 0")) {
        ps.setBytes(1, new byte[]{1});
        ps.executeQuery().close();
        TestUtil.execute(conn, "ALTER TABLE broken_binary_stream_plan ADD COLUMN b int");
        ps.setBinaryStream(1, new ByteArrayInputStream(new byte[SPOOLED_LENGTH]));
        SQLException e = assertThrows(SQLException.class, ps::executeQuery,
            "the retry can't send the released value");
        assertEquals(PSQLState.INVALID_PARAMETER_VALUE.getState(), e.getSQLState(),
            "a released value must be reported as a failed Bind");
      }
      assertFalse(conn.isClosed(), "a failed Bind must not close the connection");
      assertConnectionAnswersItsOwnQuery(conn);
    }
  }

  private static void insert(Connection conn, Shape shape, Failure failure) throws SQLException {
    try (PreparedStatement ps = conn.prepareStatement("INSERT INTO " + TABLE + " (b) VALUES (?)")) {
      switch (shape) {
        case SINGLE:
          ps.setBinaryStream(1, brokenStream(failure), DECLARED_LENGTH);
          ps.executeUpdate();
          break;
        case BATCH_LAST_ENTRY_FAILS:
          ps.setBinaryStream(1, new ByteArrayInputStream(new byte[DECLARED_LENGTH]),
              DECLARED_LENGTH);
          ps.addBatch();
          ps.setBinaryStream(1, brokenStream(failure), DECLARED_LENGTH);
          ps.addBatch();
          ps.executeBatch();
          break;
        case BATCH_FIRST_ENTRY_FAILS:
          ps.setBinaryStream(1, brokenStream(failure), DECLARED_LENGTH);
          ps.addBatch();
          ps.setBinaryStream(1, new ByteArrayInputStream(new byte[DECLARED_LENGTH]),
              DECLARED_LENGTH);
          ps.addBatch();
          ps.executeBatch();
          break;
        default:
          throw new IllegalArgumentException("Unexpected shape " + shape);
      }
    }
  }

  private static InputStream brokenStream(Failure failure) {
    switch (failure) {
      case READ_THROWS:
        return new BrokenInputStream(new ByteArrayInputStream(new byte[DECLARED_LENGTH]), 1);
      case SHORTER_THAN_DECLARED:
        return new ByteArrayInputStream(new byte[DECLARED_LENGTH - 1]);
      default:
        throw new IllegalArgumentException("Unexpected failure " + failure);
    }
  }

  private static void assertConnectionAnswersItsOwnQuery(Connection conn) throws SQLException {
    try (Statement st = conn.createStatement();
         ResultSet rs = st.executeQuery("SELECT 42")) {
      assertTrue(rs.next(), "the connection must answer its own query");
      assertEquals(42, rs.getInt(1), "the connection must answer its own query");
    }
  }

  /**
   * Opens a connection that uses unnamed statements only, so the messages are laid out as
   * {@link #smuggledQuery(int)} expects. The connection holds a session lock until its backend
   * exits.
   */
  private static Connection openAttackedConnection() throws SQLException {
    Properties props = new Properties();
    PGProperty.PREFER_QUERY_MODE.set(props, PreferQueryMode.EXTENDED.value());
    PGProperty.PREPARE_THRESHOLD.set(props, 0);
    Connection conn = TestUtil.openDB(props);
    try {
      TestUtil.execute(conn, "SELECT pg_advisory_lock(" + ATTACKED_BACKEND_LOCK + ")");
    } catch (SQLException e) {
      conn.close();
      throw e;
    }
    return conn;
  }

  private static byte[] selectValue(Connection conn, byte[] value) throws SQLException {
    try (PreparedStatement ps = conn.prepareStatement("SELECT ?")) {
      ps.setBytes(1, value);
      try (ResultSet rs = ps.executeQuery()) {
        assertTrue(rs.next());
        return rs.getBytes(1);
      }
    }
  }

  /**
   * Builds a value for {@code SELECT ?} that ends with a Sync and a Query message. If the
   * connection left a Bind with {@code pendingLength} bytes of its value unsent, the backend takes
   * the rest of that Bind from the start of the next request: its Parse and Bind header, then the
   * leading zeros of this value. The zeros also make the result format count of that Bind zero.
   * The backend then reads the tail of this value as the next messages.
   */
  private static byte[] smuggledQuery(int pendingLength) {
    byte[] sql = ("CREATE TABLE " + SMUGGLED_TABLE + " (id int)").getBytes(StandardCharsets.UTF_8);
    ByteBuffer messages = ByteBuffer.allocate(1 + 4 + 1 + 4 + sql.length + 1);
    messages.put((byte) 'S').putInt(4);
    messages.put((byte) 'Q').putInt(4 + sql.length + 1).put(sql).put((byte) 0);
    // The rest of the broken Bind: its value and the result format count
    int offset = pendingLength + 2 - PARSE_SELECT_PARAM_LENGTH - BIND_HEADER_LENGTH;
    byte[] value = new byte[offset + messages.capacity()];
    System.arraycopy(messages.array(), 0, value, offset, messages.capacity());
    return value;
  }

  private static void assertSmuggledQueryDidNotRun() throws SQLException {
    try (Connection conn = TestUtil.openDB()) {
      // The lock is free once the backend of the attacked connection has exited, and by then it
      // has run every message it read
      TestUtil.execute(conn, "SET statement_timeout = 60000");
      TestUtil.execute(conn, "SELECT pg_advisory_lock(" + ATTACKED_BACKEND_LOCK + ")");
      TestUtil.execute(conn, "SELECT pg_advisory_unlock(" + ATTACKED_BACKEND_LOCK + ")");
      try (Statement st = conn.createStatement();
           ResultSet rs = st.executeQuery(
               "SELECT count(*) FROM pg_class WHERE relname = '" + SMUGGLED_TABLE + "'")) {
        assertTrue(rs.next());
        assertEquals(0, rs.getInt(1),
            "the backend must not run a Query message from the value of a parameter");
      }
    }
  }
}
