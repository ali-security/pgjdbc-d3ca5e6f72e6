/*
 * Copyright (c) 2003, PostgreSQL Global Development Group
 * See the LICENSE file in the project root for more information.
 */

package org.postgresql.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.postgresql.jdbc.EscapeSyntaxCallMode;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.sql.SQLException;
import java.util.Arrays;
import java.util.List;

/**
 * Test cases for the Parser.
 * @author Jeremy Whiting jwhiting@redhat.com
 */
class ParserTest {

  /**
   * Test to make sure delete command is detected by parser and detected via
   * api. Mix up the case of the command to check detection continues to work.
   */
  @Test
  void deleteCommandParsing() {
    char[] command = new char[6];
    "DELETE".getChars(0, 6, command, 0);
    assertTrue(Parser.parseDeleteKeyword(command, 0), "Failed to correctly parse upper case command.");
    "DelEtE".getChars(0, 6, command, 0);
    assertTrue(Parser.parseDeleteKeyword(command, 0), "Failed to correctly parse mixed case command.");
    "deleteE".getChars(0, 6, command, 0);
    assertTrue(Parser.parseDeleteKeyword(command, 0), "Failed to correctly parse mixed case command.");
    "delete".getChars(0, 6, command, 0);
    assertTrue(Parser.parseDeleteKeyword(command, 0), "Failed to correctly parse lower case command.");
    "Delete".getChars(0, 6, command, 0);
    assertTrue(Parser.parseDeleteKeyword(command, 0), "Failed to correctly parse mixed case command.");
  }

  /**
   * Test UPDATE command parsing.
   */
  @Test
  void updateCommandParsing() {
    char[] command = new char[6];
    "UPDATE".getChars(0, 6, command, 0);
    assertTrue(Parser.parseUpdateKeyword(command, 0), "Failed to correctly parse upper case command.");
    "UpDateE".getChars(0, 6, command, 0);
    assertTrue(Parser.parseUpdateKeyword(command, 0), "Failed to correctly parse mixed case command.");
    "updatE".getChars(0, 6, command, 0);
    assertTrue(Parser.parseUpdateKeyword(command, 0), "Failed to correctly parse mixed case command.");
    "Update".getChars(0, 6, command, 0);
    assertTrue(Parser.parseUpdateKeyword(command, 0), "Failed to correctly parse mixed case command.");
    "update".getChars(0, 6, command, 0);
    assertTrue(Parser.parseUpdateKeyword(command, 0), "Failed to correctly parse lower case command.");
  }

  /**
   * Test MOVE command parsing.
   */
  @Test
  void moveCommandParsing() {
    char[] command = new char[4];
    "MOVE".getChars(0, 4, command, 0);
    assertTrue(Parser.parseMoveKeyword(command, 0), "Failed to correctly parse upper case command.");
    "mOVe".getChars(0, 4, command, 0);
    assertTrue(Parser.parseMoveKeyword(command, 0), "Failed to correctly parse mixed case command.");
    "movE".getChars(0, 4, command, 0);
    assertTrue(Parser.parseMoveKeyword(command, 0), "Failed to correctly parse mixed case command.");
    "Move".getChars(0, 4, command, 0);
    assertTrue(Parser.parseMoveKeyword(command, 0), "Failed to correctly parse mixed case command.");
    "move".getChars(0, 4, command, 0);
    assertTrue(Parser.parseMoveKeyword(command, 0), "Failed to correctly parse lower case command.");
  }

  /**
   * Test WITH command parsing.
   */
  @Test
  void withCommandParsing() {
    char[] command = new char[4];
    "WITH".getChars(0, 4, command, 0);
    assertTrue(Parser.parseWithKeyword(command, 0), "Failed to correctly parse upper case command.");
    "wITh".getChars(0, 4, command, 0);
    assertTrue(Parser.parseWithKeyword(command, 0), "Failed to correctly parse mixed case command.");
    "witH".getChars(0, 4, command, 0);
    assertTrue(Parser.parseWithKeyword(command, 0), "Failed to correctly parse mixed case command.");
    "With".getChars(0, 4, command, 0);
    assertTrue(Parser.parseWithKeyword(command, 0), "Failed to correctly parse mixed case command.");
    "with".getChars(0, 4, command, 0);
    assertTrue(Parser.parseWithKeyword(command, 0), "Failed to correctly parse lower case command.");
  }

  /**
   * Test SELECT command parsing.
   */
  @Test
  void selectCommandParsing() {
    char[] command = new char[6];
    "SELECT".getChars(0, 6, command, 0);
    assertTrue(Parser.parseSelectKeyword(command, 0), "Failed to correctly parse upper case command.");
    "sELect".getChars(0, 6, command, 0);
    assertTrue(Parser.parseSelectKeyword(command, 0), "Failed to correctly parse mixed case command.");
    "selecT".getChars(0, 6, command, 0);
    assertTrue(Parser.parseSelectKeyword(command, 0), "Failed to correctly parse mixed case command.");
    "Select".getChars(0, 6, command, 0);
    assertTrue(Parser.parseSelectKeyword(command, 0), "Failed to correctly parse mixed case command.");
    "select".getChars(0, 6, command, 0);
    assertTrue(Parser.parseSelectKeyword(command, 0), "Failed to correctly parse lower case command.");
  }

  @Test
  void escapeProcessing() throws Exception {
    assertEquals("DATE '1999-01-09'", Parser.replaceProcessing("{d '1999-01-09'}", true, false));
    assertEquals("DATE '1999-01-09'", Parser.replaceProcessing("{D  '1999-01-09'}", true, false));
    assertEquals("TIME '20:00:03'", Parser.replaceProcessing("{t '20:00:03'}", true, false));
    assertEquals("TIME '20:00:03'", Parser.replaceProcessing("{T '20:00:03'}", true, false));
    assertEquals("TIMESTAMP '1999-01-09 20:11:11.123455'", Parser.replaceProcessing("{ts '1999-01-09 20:11:11.123455'}", true, false));
    assertEquals("TIMESTAMP '1999-01-09 20:11:11.123455'", Parser.replaceProcessing("{Ts '1999-01-09 20:11:11.123455'}", true, false));

    assertEquals("user", Parser.replaceProcessing("{fn user()}", true, false));
    assertEquals("cos(1)", Parser.replaceProcessing("{fn cos(1)}", true, false));
    assertEquals("extract(week from DATE '2005-01-24')", Parser.replaceProcessing("{fn week({d '2005-01-24'})}", true, false));

    assertEquals("\"T1\" LEFT OUTER JOIN t2 ON \"T1\".id = t2.id",
            Parser.replaceProcessing("{oj \"T1\" LEFT OUTER JOIN t2 ON \"T1\".id = t2.id}", true, false));

    assertEquals("ESCAPE '_'", Parser.replaceProcessing("{escape '_'}", true, false));

    // nothing should be changed in that case, no valid escape code
    assertEquals("{obj : 1}", Parser.replaceProcessing("{obj : 1}", true, false));
  }

  @Test
  void modifyJdbcCall() throws SQLException {
    assertEquals("select * from pack_getValue(?) as result", Parser.modifyJdbcCall("{ ? = call pack_getValue}", true, ServerVersion.v9_6.getVersionNum(), 3, EscapeSyntaxCallMode.SELECT).getSql());
    assertEquals("select * from pack_getValue(?,?)  as result", Parser.modifyJdbcCall("{ ? = call pack_getValue(?) }", true, ServerVersion.v9_6.getVersionNum(), 3, EscapeSyntaxCallMode.SELECT).getSql());
    assertEquals("select * from pack_getValue(?) as result", Parser.modifyJdbcCall("{ ? = call pack_getValue()}", true, ServerVersion.v9_6.getVersionNum(), 3, EscapeSyntaxCallMode.SELECT).getSql());
    assertEquals("select * from pack_getValue(?,?,?,?)  as result", Parser.modifyJdbcCall("{ ? = call pack_getValue(?,?,?) }", true, ServerVersion.v9_6.getVersionNum(), 3, EscapeSyntaxCallMode.SELECT).getSql());
    assertEquals("select * from lower(?,?) as result", Parser.modifyJdbcCall("{ ? = call lower(?)}", true, ServerVersion.v9_6.getVersionNum(), 3, EscapeSyntaxCallMode.SELECT).getSql());
    assertEquals("select * from lower(?,?) as result", Parser.modifyJdbcCall("{ ? = call lower(?)}", true, ServerVersion.v9_6.getVersionNum(), 3, EscapeSyntaxCallMode.CALL_IF_NO_RETURN).getSql());
    assertEquals("select * from lower(?,?) as result", Parser.modifyJdbcCall("{ ? = call lower(?)}", true, ServerVersion.v9_6.getVersionNum(), 3, EscapeSyntaxCallMode.CALL).getSql());
    assertEquals("select * from lower(?,?) as result", Parser.modifyJdbcCall("{call lower(?,?)}", true, ServerVersion.v9_6.getVersionNum(), 3, EscapeSyntaxCallMode.SELECT).getSql());
    assertEquals("select * from lower(?,?) as result", Parser.modifyJdbcCall("{call lower(?,?)}", true, ServerVersion.v9_6.getVersionNum(), 3, EscapeSyntaxCallMode.CALL_IF_NO_RETURN).getSql());
    assertEquals("select * from lower(?,?) as result", Parser.modifyJdbcCall("{call lower(?,?)}", true, ServerVersion.v9_6.getVersionNum(), 3, EscapeSyntaxCallMode.CALL).getSql());
    assertEquals("select * from lower(?,?) as result", Parser.modifyJdbcCall("{ ? = call lower(?)}", true, ServerVersion.v11.getVersionNum(), 3, EscapeSyntaxCallMode.SELECT).getSql());
    assertEquals("select * from lower(?,?) as result", Parser.modifyJdbcCall("{ ? = call lower(?)}", true, ServerVersion.v11.getVersionNum(), 3, EscapeSyntaxCallMode.CALL_IF_NO_RETURN).getSql());
    assertEquals("call lower(?,?)", Parser.modifyJdbcCall("{ ? = call lower(?)}", true, ServerVersion.v11.getVersionNum(), 3, EscapeSyntaxCallMode.CALL).getSql());
    assertEquals("select * from lower(?,?) as result", Parser.modifyJdbcCall("{call lower(?,?)}", true, ServerVersion.v11.getVersionNum(), 3, EscapeSyntaxCallMode.SELECT).getSql());
    assertEquals("call lower(?,?)", Parser.modifyJdbcCall("{call lower(?,?)}", true, ServerVersion.v11.getVersionNum(), 3, EscapeSyntaxCallMode.CALL_IF_NO_RETURN).getSql());
    assertEquals("call lower(?,?)", Parser.modifyJdbcCall("{call lower(?,?)}", true, ServerVersion.v11.getVersionNum(), 3, EscapeSyntaxCallMode.CALL).getSql());
  }

  @Test
  void unterminatedEscape() throws Exception {
    assertEquals("{oj ", Parser.replaceProcessing("{oj ", true, false));
  }

  /**
   * A brace inside a literal, quoted identifier, dollar quote or comment does not end a JDBC
   * escape, and the text after the arguments of {@code {fn ...}} is not copied up to the first
   * brace either.
   */
  @Test
  void escapeDoesNotEndAtBraceInsideLiteral() throws SQLException {
    assertEquals("DATE '2020-}'", Parser.replaceProcessing("{d '2020-}'}", true, false));
    assertEquals("TIME '20:00:}'", Parser.replaceProcessing("{t '20:00:}'}", true, false));
    assertEquals("TIMESTAMP '2020-01-01 }'",
        Parser.replaceProcessing("{ts '2020-01-01 }'}", true, false));
    assertEquals("ESCAPE '}'", Parser.replaceProcessing("{escape '}'}", true, false));
    assertEquals("t1 LEFT OUTER JOIN t2 ON t1.s = '}'",
        Parser.replaceProcessing("{oj t1 LEFT OUTER JOIN t2 ON t1.s = '}'}", true, false));
    assertEquals("t1 LEFT OUTER JOIN t2 ON t1.s = \"}\"",
        Parser.replaceProcessing("{oj t1 LEFT OUTER JOIN t2 ON t1.s = \"}\"}", true, false));
    assertEquals("t1 LEFT OUTER JOIN t2 ON t1.s = $$}$$",
        Parser.replaceProcessing("{oj t1 LEFT OUTER JOIN t2 ON t1.s = $$}$$}", true, false));
    assertEquals("cos(1) /* } */", Parser.replaceProcessing("{fn cos(1) /* } */}", true, false));
    assertEquals("cos(1) -- }\n", Parser.replaceProcessing("{fn cos(1) -- }\n}", true, false));
  }

  /**
   * A quoted value with doubled quotes must stay inside the literal of the escape: the escapes in
   * it must not be translated, and it must not be able to move the closing quote.
   */
  @Test
  void escapeKeepsQuotedValueInsideLiteral() throws SQLException {
    assertEquals("DATE '}'' {fn ucase(''x'')} --'",
        Parser.replaceProcessing("{d '}'' {fn ucase(''x'')} --'}", true, false));
    assertEquals("DATE '}'' {fn ucase(''x'')} --'",
        Parser.replaceProcessing("{d '}'' {fn ucase(''x'')} --'}", true, true));
    assertEquals("t1 LEFT OUTER JOIN t2 ON t2.name = '}{fn locate(''a'',''b'',1)}'",
        Parser.replaceProcessing(
            "{oj t1 LEFT OUTER JOIN t2 ON t2.name = '}{fn locate(''a'',''b'',1)}'}", true, true));
  }

  @Test
  void unterminatedLiteralInsideEscape() {
    assertThrows(SQLException.class,
        () -> Parser.replaceProcessing("{d '2020-01-01}", true, false));
    assertThrows(SQLException.class,
        () -> Parser.replaceProcessing("{fn cos(1) '}", true, false));
  }

  /**
   * The backend treats every non-ASCII character as an identifier character, so the parser must
   * agree with it on where a dollar quote starts.
   */
  @Test
  void dollarQuoteUsesBackendIdentifierCharacters() throws SQLException {
    // Non-ASCII characters that are not Java identifier characters can be part of a tag
    assertBindCount(0, "SELECT $×$ ? $×$");
    assertBindCount(0, "SELECT $a😀$ ? $a😀$");
    assertEquals(1,
        Parser.parseJdbcSql("SELECT $×$;$×$", true, true, true, false, false).size());
    assertEquals("SELECT $×${fn ucase('a')}$×$",
        Parser.replaceProcessing("SELECT $×${fn ucase('a')}$×$", true, true));
    // A $ after a non-ASCII character continues the identifier
    assertBindCount(1, "SELECT a×$$ ? $$");
    assertBindCount(1, "SELECT 😀$$ ? $$");
    // A control character does not continue an identifier
    assertBindCount(0, "SELECT \u0001$$ ? $$");
    // An unpaired surrogate is sent as ?, so it neither continues an identifier nor a tag
    assertBindCount(0, "SELECT \uD800$$ ? $$");
    assertBindCount(1, "SELECT $a\uD800$ ? $a\uD800$");
  }

  /**
   * A doubled quote and a continuation on a new line do not end a single-quoted string, and the
   * rest of the string follows the rules of its first part.
   */
  @Test
  void singleQuotedStringFollowsBackendRules() throws SQLException {
    assertBindCount(0, "SELECT E'a''\\' ? '");
    assertBindCount(0, "SELECT E'a'\n'\\' ? '");
    assertBindCount(0, "SELECT E'a'\r\n  '\\' ? '");
    assertBindCount(0, "SELECT E'a' -- comment\n'\\' ? '");
    assertBindCount(0, "SELECT E'a'\n\u000B'\\' ? '");
    // Without a newline there is no continuation
    assertBindCount(1, "SELECT E'a' '\\' ? '");
    assertBindCount(1, "SELECT E'a' /* comment */\n'\\' ? '");
    // A vertical tab and an unpaired surrogate end the identifier before E'
    assertBindCount(0, "SELECT\u000BE'\\' ? '");
    assertBindCount(0, "SELECT \uD800E'\\' ? '");
    // Statement separators and escapes inside the string are left alone
    assertEquals(1,
        Parser.parseJdbcSql("SELECT E'a''\\'; SELECT 1; --'", true, true, true, false, false).size());
    assertEquals("SELECT E'a''\\' {fn ucase(''x'')} '",
        Parser.replaceProcessing("SELECT E'a''\\' {fn ucase(''x'')} '", true, true));
  }

  /**
   * A subtracted argument that starts with a minus sign must not create a {@code --} comment.
   */
  @Test
  void subtractedEscapeFunctionArgumentIsParenthesized() throws SQLException {
    String right = Parser.replaceProcessing("{fn right('abc',-1)}", true, false);
    assertEquals("substring('abc' from (length('abc')+1-(-1)))", right);
    assertFalse(right.contains("--"), right);
    String timestampdiff =
        Parser.replaceProcessing("{fn timestampdiff(SQL_TSI_DAY,-a,b)}", true, false);
    assertEquals("extract( day from ((b)-(-a)))", timestampdiff);
    assertFalse(timestampdiff.contains("--"), timestampdiff);
  }

  @Test
  @SuppressWarnings("deprecation")
  void deprecatedEscapedFunctionsParenthesizeSubtractedArgument() throws SQLException {
    assertEquals("substring('abc' from (length('abc')+1-(-1)))",
        org.postgresql.jdbc.EscapedFunctions.sqlright(Arrays.asList("'abc'", "-1")));
    assertEquals("extract( day from ((b)-(-a)))",
        org.postgresql.jdbc.EscapedFunctions.sqltimestampdiff(
            Arrays.asList("SQL_TSI_DAY", "-a", "b")));
  }

  private static void assertBindCount(int expected, String query) throws SQLException {
    List<NativeQuery> qry = Parser.parseJdbcSql(query, true, true, true, false, false);
    assertEquals(1, qry.size(), "number of statements in " + query);
    assertEquals(expected, qry.get(0).bindPositions.length, "number of placeholders in " + query);
  }

  @Test
  @Disabled(value = "returning in the select clause is hard to distinguish from insert ... returning *")
  void insertSelectFakeReturning() throws SQLException {
    String query =
        "insert test(id, name) select 1, 'value' as RETURNING from test2";
    List<NativeQuery> qry =
        Parser.parseJdbcSql(
            query, true, true, true, true, true);
    boolean returningKeywordPresent = qry.get(0).command.isReturningKeywordPresent();
    assertFalse(returningKeywordPresent, "Query does not have returning clause " + query);
  }

  @Test
  void insertSelectReturning() throws SQLException {
    String query =
        "insert test(id, name) select 1, 'value' from test2 RETURNING id";
    List<NativeQuery> qry =
        Parser.parseJdbcSql(
            query, true, true, true, true, true);
    boolean returningKeywordPresent = qry.get(0).command.isReturningKeywordPresent();
    assertTrue(returningKeywordPresent, "Query has a returning clause " + query);
  }

  @Test
  void insertReturningInWith() throws SQLException {
    String query =
        "with x as (insert into mytab(x) values(1) returning x) insert test(id, name) select 1, 'value' from test2";
    List<NativeQuery> qry =
        Parser.parseJdbcSql(
            query, true, true, true, true, true);
    boolean returningKeywordPresent = qry.get(0).command.isReturningKeywordPresent();
    assertFalse(returningKeywordPresent, "There's no top-level <<returning>> clause " + query);
  }

  @Test
  void insertBatchedReWriteOnConflict() throws SQLException {
    String query = "insert into test(id, name) values (:id,:name) ON CONFLICT (id) DO NOTHING";
    List<NativeQuery> qry = Parser.parseJdbcSql(query, true, true, true, true, true);
    SqlCommand command = qry.get(0).getCommand();
    assertEquals(34, command.getBatchRewriteValuesBraceOpenPosition());
    assertEquals(44, command.getBatchRewriteValuesBraceClosePosition());
  }

  @Test
  void insertBatchedReWriteOnConflictUpdateBind() throws SQLException {
    String query = "insert into test(id, name) values (?,?) ON CONFLICT (id) UPDATE SET name=?";
    List<NativeQuery> qry = Parser.parseJdbcSql(query, true, true, true, true, true);
    SqlCommand command = qry.get(0).getCommand();
    assertFalse(command.isBatchedReWriteCompatible(), "update set name=? is NOT compatible with insert rewrite");
  }

  @Test
  void insertBatchedReWriteOnConflictUpdateConstant() throws SQLException {
    String query = "insert into test(id, name) values (?,?) ON CONFLICT (id) UPDATE SET name='default'";
    List<NativeQuery> qry = Parser.parseJdbcSql(query, true, true, true, true, true);
    SqlCommand command = qry.get(0).getCommand();
    assertTrue(command.isBatchedReWriteCompatible(), "update set name='default' is compatible with insert rewrite");
  }

  @Test
  void insertMultiInsert() throws SQLException {
    String query =
        "insert into test(id, name) values (:id,:name),(:id,:name) ON CONFLICT (id) DO NOTHING";
    List<NativeQuery> qry = Parser.parseJdbcSql(query, true, true, true, true, true);
    SqlCommand command = qry.get(0).getCommand();
    assertEquals(34, command.getBatchRewriteValuesBraceOpenPosition());
    assertEquals(56, command.getBatchRewriteValuesBraceClosePosition());
  }

  @Test
  void valuesTableParse() throws SQLException {
    String query = "insert into values_table (id, name) values (?,?)";
    List<NativeQuery> qry = Parser.parseJdbcSql(query, true, true, true, true, true);
    SqlCommand command = qry.get(0).getCommand();
    assertEquals(43, command.getBatchRewriteValuesBraceOpenPosition());
    assertEquals(49, command.getBatchRewriteValuesBraceClosePosition());

    query = "insert into table_values (id, name) values (?,?)";
    qry = Parser.parseJdbcSql(query, true, true, true, true, true);
    command = qry.get(0).getCommand();
    assertEquals(43, command.getBatchRewriteValuesBraceOpenPosition());
    assertEquals(49, command.getBatchRewriteValuesBraceClosePosition());
  }

  @Test
  void createTableParseWithOnDeleteClause() throws SQLException {
    String[] returningColumns = {"*"};
    String query = "create table \"testTable\" (\"id\" INT SERIAL NOT NULL PRIMARY KEY, \"foreignId\" INT REFERENCES \"otherTable\" (\"id\") ON DELETE NO ACTION)";
    List<NativeQuery> qry = Parser.parseJdbcSql(query, true, true, true, true, true, returningColumns);
    SqlCommand command = qry.get(0).getCommand();
    assertFalse(command.isReturningKeywordPresent(), "No returning keyword should be present");
    assertEquals(SqlCommandType.CREATE, command.getType());
  }

  @Test
  void createTableParseWithOnUpdateClause() throws SQLException {
    String[] returningColumns = {"*"};
    String query = "create table \"testTable\" (\"id\" INT SERIAL NOT NULL PRIMARY KEY, \"foreignId\" INT REFERENCES \"otherTable\" (\"id\")) ON UPDATE NO ACTION";
    List<NativeQuery> qry = Parser.parseJdbcSql(query, true, true, true, true, true, returningColumns);
    SqlCommand command = qry.get(0).getCommand();
    assertFalse(command.isReturningKeywordPresent(), "No returning keyword should be present");
    assertEquals(SqlCommandType.CREATE, command.getType());
  }

  @Test
  void alterTableParseWithOnDeleteClause() throws SQLException {
    String[] returningColumns = {"*"};
    String query = "alter table \"testTable\" ADD \"foreignId\" INT REFERENCES \"otherTable\" (\"id\") ON DELETE NO ACTION";
    List<NativeQuery> qry = Parser.parseJdbcSql(query, true, true, true, true, true, returningColumns);
    SqlCommand command = qry.get(0).getCommand();
    assertFalse(command.isReturningKeywordPresent(), "No returning keyword should be present");
    assertEquals(SqlCommandType.ALTER, command.getType());
  }

  @Test
  void alterTableParseWithOnUpdateClause() throws SQLException {
    String[] returningColumns = {"*"};
    String query = "alter table \"testTable\" ADD \"foreignId\" INT REFERENCES \"otherTable\" (\"id\") ON UPDATE RESTRICT";
    List<NativeQuery> qry = Parser.parseJdbcSql(query, true, true, true, true, true, returningColumns);
    SqlCommand command = qry.get(0).getCommand();
    assertFalse(command.isReturningKeywordPresent(), "No returning keyword should be present");
    assertEquals(SqlCommandType.ALTER, command.getType());
  }

  @Test
  void parseV14functions() throws SQLException {
    String[] returningColumns = {"*"};
    String query = "CREATE OR REPLACE FUNCTION asterisks(n int)\n"
        + "  RETURNS SETOF text\n"
        + "  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE\n"
        + "BEGIN ATOMIC\n"
        + "SELECT repeat('*', g) FROM generate_series (1, n) g; \n"
        + "END;";
    List<NativeQuery> qry = Parser.parseJdbcSql(query, true, true, true, true, true, returningColumns);
    assertNotNull(qry);
    assertEquals(1, qry.size(), "There should only be one query returned here");
  }
}
