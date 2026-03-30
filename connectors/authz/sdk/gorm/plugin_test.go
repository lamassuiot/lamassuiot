package gorm

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// authzQueryKey is used in tests to match the plugin's context key.
// The plugin uses the raw string "authz_query" so we must use the same.
const authzQueryKey = "authz_query" //nolint:staticcheck

func TestAuthzGormPlugin_Name(t *testing.T) {
	assert.Equal(t, "authz-plugin", NewAuthzGormPlugin().Name())
}

func TestAuthzGormPlugin_SkipsIfAuthzQueryMissing(t *testing.T) {
	// No authz_query key in context → plugin is a no-op.
	db := testDB(t)
	require.NoError(t, NewAuthzGormPlugin().Initialize(db))

	var dest []map[string]interface{}
	sql := db.WithContext(context.Background()).Table("certificates").Find(&dest).Statement.SQL.String()

	assert.NotContains(t, strings.ToUpper(sql), "JOIN")
	assert.NotContains(t, strings.ToUpper(sql), "WHERE")
}

func TestAuthzGormPlugin_SkipsIfAuthzQueryEmpty(t *testing.T) {
	// Empty string value → plugin is a no-op.
	db := testDB(t)
	require.NoError(t, NewAuthzGormPlugin().Initialize(db))

	ctx := context.WithValue(context.Background(), authzQueryKey, "") //nolint:staticcheck
	var dest []map[string]interface{}
	sql := db.WithContext(ctx).Table("certificates").Find(&dest).Statement.SQL.String()

	assert.NotContains(t, strings.ToUpper(sql), "JOIN")
	assert.NotContains(t, strings.ToUpper(sql), "WHERE")
}

func TestAuthzGormPlugin_SkipsIfAuthzQueryNotAString(t *testing.T) {
	// Wrong type for value → plugin is a no-op (type assertion fails silently).
	db := testDB(t)
	require.NoError(t, NewAuthzGormPlugin().Initialize(db))

	ctx := context.WithValue(context.Background(), authzQueryKey, 42) //nolint:staticcheck
	var dest []map[string]interface{}
	sql := db.WithContext(ctx).Table("certificates").Find(&dest).Statement.SQL.String()

	assert.NotContains(t, strings.ToUpper(sql), "JOIN")
	assert.NotContains(t, strings.ToUpper(sql), "WHERE")
}

func TestAuthzGormPlugin_InjectsDenyAll(t *testing.T) {
	// Deny-all filter (1 = 0) must be injected into the WHERE clause.
	db := testDB(t)
	require.NoError(t, NewAuthzGormPlugin().Initialize(db))

	authzSQL := `SELECT * FROM ca.certificates WHERE 1 = 0`
	ctx := context.WithValue(context.Background(), authzQueryKey, authzSQL) //nolint:staticcheck

	var dest []map[string]interface{}
	sql := db.WithContext(ctx).Table("ca.certificates").Find(&dest).Statement.SQL.String()

	assert.Contains(t, sql, "1 = 0")
	assert.NotContains(t, strings.ToUpper(sql), "JOIN")
}

func TestAuthzGormPlugin_InjectsWildcardGrantAll(t *testing.T) {
	// Wildcard grant (1 = 1) means all rows are accessible.
	db := testDB(t)
	require.NoError(t, NewAuthzGormPlugin().Initialize(db))

	authzSQL := `SELECT * FROM ca.certificates WHERE 1 = 1`
	ctx := context.WithValue(context.Background(), authzQueryKey, authzSQL) //nolint:staticcheck

	var dest []map[string]interface{}
	sql := db.WithContext(ctx).Table("ca.certificates").Find(&dest).Statement.SQL.String()

	assert.Contains(t, sql, "1 = 1")
	assert.NotContains(t, strings.ToUpper(sql), "JOIN")
}

func TestAuthzGormPlugin_InjectsSingleHopFilter(t *testing.T) {
	// One hop: devices accessible via their DMS owner.
	db := testDB(t)
	require.NoError(t, NewAuthzGormPlugin().Initialize(db))

	authzSQL := `SELECT * FROM devicemanager.devices LEFT JOIN dmsmanager.dms AS j0_0 ON devicemanager.devices.dms_owner = j0_0.id WHERE j0_0.id = 'sample-dms-01'`
	ctx := context.WithValue(context.Background(), authzQueryKey, authzSQL) //nolint:staticcheck

	var dest []map[string]interface{}
	sql := db.WithContext(ctx).Table("devices").Find(&dest).Statement.SQL.String()

	assert.Contains(t, sql, "LEFT JOIN dmsmanager.dms AS j0_0 ON devicemanager.devices.dms_owner = j0_0.id")
	assert.Contains(t, sql, "j0_0.id = 'sample-dms-01'")
	whereAfterLastJoin(t, sql)
}

func TestAuthzGormPlugin_InjectsTwoHopFilterWithNullTest(t *testing.T) {
	// The exact post-fix scenario from the bug report:
	// dms (directGrants=["*"]) → device → certificate.
	// The WHERE uses j0_1.id IS NOT NULL (dms alias), NOT j0_0.serial_number.
	db := testDB(t)
	require.NoError(t, NewAuthzGormPlugin().Initialize(db))

	authzSQL := `SELECT * FROM ca.certificates LEFT JOIN devicemanager.devices AS j0_0 ON ca.certificates.subject_common_name = j0_0.id LEFT JOIN dmsmanager.dms AS j0_1 ON j0_0.dms_owner = j0_1.id WHERE j0_1.id IS NOT NULL`
	ctx := context.WithValue(context.Background(), authzQueryKey, authzSQL) //nolint:staticcheck

	var dest []map[string]interface{}
	sql := db.WithContext(ctx).Table("certificates").Find(&dest).Statement.SQL.String()

	assert.Contains(t, sql, "LEFT JOIN devicemanager.devices AS j0_0 ON ca.certificates.subject_common_name = j0_0.id")
	assert.Contains(t, sql, "LEFT JOIN dmsmanager.dms AS j0_1 ON j0_0.dms_owner = j0_1.id")
	assert.Contains(t, sql, "j0_1.id IS NOT NULL")
	whereAfterLastJoin(t, sql)
}

func TestAuthzGormPlugin_InjectsTwoHopFilterWithEqualityWhere(t *testing.T) {
	// Two-hop: certificates accessible via specific DMS ID grant.
	db := testDB(t)
	require.NoError(t, NewAuthzGormPlugin().Initialize(db))

	authzSQL := `SELECT * FROM ca.certificates LEFT JOIN devicemanager.devices AS j0_0 ON ca.certificates.subject_common_name = j0_0.id LEFT JOIN dmsmanager.dms AS j0_1 ON j0_0.dms_owner = j0_1.id WHERE j0_1.id = 'sample-dms-01'`
	ctx := context.WithValue(context.Background(), authzQueryKey, authzSQL) //nolint:staticcheck

	var dest []map[string]interface{}
	sql := db.WithContext(ctx).Table("certificates").Find(&dest).Statement.SQL.String()

	assert.Contains(t, sql, "LEFT JOIN devicemanager.devices AS j0_0 ON ca.certificates.subject_common_name = j0_0.id")
	assert.Contains(t, sql, "LEFT JOIN dmsmanager.dms AS j0_1 ON j0_0.dms_owner = j0_1.id")
	assert.Contains(t, sql, "j0_1.id = 'sample-dms-01'")
	whereAfterLastJoin(t, sql)
}

func TestAuthzGormPlugin_InjectsSingleHopFilterDeviceRevoke(t *testing.T) {
	// Filter generated by device-007 rule granting status-update/revoke on certificates:
	// single JOIN to devices, WHERE j0_0.id = 'device-007'.
	db := testDB(t)
	require.NoError(t, NewAuthzGormPlugin().Initialize(db))

	authzSQL := `SELECT * FROM ca.certificates LEFT JOIN devicemanager.devices AS j0_0 ON ca.certificates.subject_common_name = j0_0.id WHERE j0_0.id = 'device-007'`
	ctx := context.WithValue(context.Background(), authzQueryKey, authzSQL) //nolint:staticcheck

	var dest []map[string]interface{}
	sql := db.WithContext(ctx).Table("certificates").Find(&dest).Statement.SQL.String()

	assert.Contains(t, sql, "LEFT JOIN devicemanager.devices AS j0_0 ON ca.certificates.subject_common_name = j0_0.id")
	assert.Contains(t, sql, "j0_0.id = 'device-007'")
	whereAfterLastJoin(t, sql)
}
