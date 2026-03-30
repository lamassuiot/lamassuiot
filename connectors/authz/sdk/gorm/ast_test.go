package gorm

import (
	"strings"
	"testing"

	pg_query "github.com/pganalyze/pg_query_go/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// testDB returns a GORM DB in dry-run mode backed by an in-memory SQLite instance.
// DryRun builds SQL strings without executing them, so no real tables are needed.
func testDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	require.NoError(t, err)
	return db.Session(&gorm.Session{DryRun: true})
}

// applyAuthzSQL parses authzSQL, injects it into a base query for the given table,
// and returns the final SQL string GORM would send to the database.
func applyAuthzSQL(t *testing.T, db *gorm.DB, table, authzSQL string) string {
	t.Helper()
	ast, err := pg_query.Parse(authzSQL)
	require.NoError(t, err)
	var dest []map[string]interface{}
	result := AddASTToQuery(db.Table(table), ast, authzSQL).Find(&dest)
	return result.Statement.SQL.String()
}

// whereAfterLastJoin asserts the WHERE clause appears after the last JOIN in sql.
// This guards against the regression where the WHERE was embedded in the last JOIN string.
func whereAfterLastJoin(t *testing.T, sql string) {
	t.Helper()
	upper := strings.ToUpper(sql)
	lastJoin := strings.LastIndex(upper, "JOIN")
	where := strings.Index(upper, "WHERE")
	require.NotEqual(t, -1, where, "expected a WHERE clause in: %s", sql)
	assert.Greater(t, where, lastJoin, "WHERE must appear after the last JOIN\nSQL: %s", sql)
}

func TestAddASTToQuery_NilAST(t *testing.T) {
	db := testDB(t)
	var dest []map[string]interface{}
	result := AddASTToQuery(db.Table("certificates"), nil, "").Find(&dest)
	sql := result.Statement.SQL.String()
	assert.NotContains(t, strings.ToUpper(sql), "JOIN")
	assert.NotContains(t, strings.ToUpper(sql), "WHERE")
}

func TestAddASTToQuery_EmptyStmts(t *testing.T) {
	db := testDB(t)
	var dest []map[string]interface{}
	result := AddASTToQuery(db.Table("certificates"), &pg_query.ParseResult{}, "").Find(&dest)
	sql := result.Statement.SQL.String()
	assert.NotContains(t, strings.ToUpper(sql), "JOIN")
	assert.NotContains(t, strings.ToUpper(sql), "WHERE")
}

func TestAddASTToQuery_WildcardGrantNoJoins(t *testing.T) {
	// Direct wildcard on the target entity type itself: WHERE 1 = 1, no JOINs.
	authzSQL := `SELECT * FROM ca.certificates WHERE 1 = 1`
	sql := applyAuthzSQL(t, testDB(t), "certificates", authzSQL)

	assert.NotContains(t, strings.ToUpper(sql), "JOIN")
	assert.Contains(t, sql, "1 = 1")
}

func TestAddASTToQuery_DenyAllNoJoins(t *testing.T) {
	// Deny-all condition: WHERE 1 = 0.
	authzSQL := `SELECT * FROM ca.certificates WHERE 1 = 0`
	sql := applyAuthzSQL(t, testDB(t), "certificates", authzSQL)

	assert.NotContains(t, strings.ToUpper(sql), "JOIN")
	assert.Contains(t, sql, "1 = 0")
}

func TestAddASTToQuery_SingleJoinNullTest(t *testing.T) {
	// One-hop JOIN + IS NOT NULL (NullTest node).
	// getLoc must handle NullTest; otherwise whereStart=-1 and the WHERE ends up
	// embedded in the last JOIN string instead of being a proper WHERE clause.
	authzSQL := `SELECT * FROM devicemanager.devices LEFT JOIN dmsmanager.dms AS j0_0 ON devicemanager.devices.dms_owner = j0_0.id WHERE j0_0.id IS NOT NULL`
	sql := applyAuthzSQL(t, testDB(t), "devices", authzSQL)

	assert.Contains(t, sql, "LEFT JOIN dmsmanager.dms AS j0_0 ON devicemanager.devices.dms_owner = j0_0.id")
	assert.Contains(t, sql, "j0_0.id IS NOT NULL")
	whereAfterLastJoin(t, sql)
}

func TestAddASTToQuery_TwoHopJoinNullTest(t *testing.T) {
	// The exact scenario from the bug report:
	// dms (directGrants=["*"]) → device → certificate, querying certificates.
	// After the filter.go fix, the WHERE is j0_1.id IS NOT NULL (dms alias, NullTest).
	authzSQL := `SELECT * FROM ca.certificates LEFT JOIN devicemanager.devices AS j0_0 ON ca.certificates.subject_common_name = j0_0.id LEFT JOIN dmsmanager.dms AS j0_1 ON j0_0.dms_owner = j0_1.id WHERE j0_1.id IS NOT NULL`
	sql := applyAuthzSQL(t, testDB(t), "certificates", authzSQL)

	assert.Contains(t, sql, "LEFT JOIN devicemanager.devices AS j0_0 ON ca.certificates.subject_common_name = j0_0.id")
	assert.Contains(t, sql, "LEFT JOIN dmsmanager.dms AS j0_1 ON j0_0.dms_owner = j0_1.id")
	assert.Contains(t, sql, "j0_1.id IS NOT NULL")
	whereAfterLastJoin(t, sql)
}

func TestAddASTToQuery_SingleJoinEqualityWhere(t *testing.T) {
	// One-hop JOIN + equality WHERE (A_Expr): specific entity ID grant.
	authzSQL := `SELECT * FROM devicemanager.devices LEFT JOIN dmsmanager.dms AS j0_0 ON devicemanager.devices.dms_owner = j0_0.id WHERE j0_0.id = 'sample-dms-01'`
	sql := applyAuthzSQL(t, testDB(t), "devices", authzSQL)

	assert.Contains(t, sql, "LEFT JOIN dmsmanager.dms AS j0_0 ON devicemanager.devices.dms_owner = j0_0.id")
	assert.Contains(t, sql, "j0_0.id = 'sample-dms-01'")
	whereAfterLastJoin(t, sql)
}

func TestAddASTToQuery_TwoHopJoinEqualityWhere(t *testing.T) {
	// Two-hop JOIN + equality WHERE: specific DMS ID cascading to certificates.
	authzSQL := `SELECT * FROM ca.certificates LEFT JOIN devicemanager.devices AS j0_0 ON ca.certificates.subject_common_name = j0_0.id LEFT JOIN dmsmanager.dms AS j0_1 ON j0_0.dms_owner = j0_1.id WHERE j0_1.id = 'sample-dms-01'`
	sql := applyAuthzSQL(t, testDB(t), "certificates", authzSQL)

	assert.Contains(t, sql, "LEFT JOIN devicemanager.devices AS j0_0 ON ca.certificates.subject_common_name = j0_0.id")
	assert.Contains(t, sql, "LEFT JOIN dmsmanager.dms AS j0_1 ON j0_0.dms_owner = j0_1.id")
	assert.Contains(t, sql, "j0_1.id = 'sample-dms-01'")
	whereAfterLastJoin(t, sql)
}

func TestAddASTToQuery_NoJoinWithInClause(t *testing.T) {
	// Direct grants with specific IDs: WHERE ... IN (...), no JOINs (A_Expr AEXPR_IN).
	authzSQL := `SELECT * FROM dmsmanager.dms WHERE dmsmanager.dms.id IN ('dms-1', 'dms-2')`
	sql := applyAuthzSQL(t, testDB(t), "dms", authzSQL)

	assert.NotContains(t, strings.ToUpper(sql), "JOIN")
	assert.Contains(t, sql, "dmsmanager.dms.id IN ('dms-1', 'dms-2')")
}

func TestAddASTToQuery_JoinStringContainsNoWhereKeyword(t *testing.T) {
	// Explicitly assert that neither JOIN clause string contains the WHERE keyword.
	// This is the core regression: before the NullTest fix, the WHERE was stitched
	// onto the end of the last Joins() call.
	authzSQL := `SELECT * FROM ca.certificates LEFT JOIN devicemanager.devices AS j0_0 ON ca.certificates.subject_common_name = j0_0.id LEFT JOIN dmsmanager.dms AS j0_1 ON j0_0.dms_owner = j0_1.id WHERE j0_1.id IS NOT NULL`
	sql := applyAuthzSQL(t, testDB(t), "certificates", authzSQL)

	// Split on WHERE to get the JOINs-only portion and check it has no stray WHERE.
	upper := strings.ToUpper(sql)
	whereIdx := strings.Index(upper, "WHERE")
	require.NotEqual(t, -1, whereIdx, "expected WHERE in generated SQL")
	joinsPart := sql[:whereIdx]
	assert.NotContains(t, strings.ToUpper(joinsPart), "WHERE",
		"WHERE keyword must not appear inside the JOIN section\nJOINs part: %s", joinsPart)
}
