package gorm

import (
	"context"
	"strings"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/engine"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/models"
	authzsdk "github.com/lamassuiot/lamassuiot/v4/connectors/authz/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthzGormPlugin_Name(t *testing.T) {
	assert.Equal(t, "authz-plugin", NewAuthzGormPlugin().Name())
}

func TestAuthzGormPlugin_SkipsIfAuthzQueryMissing(t *testing.T) {
	// No authz_query key in context → plugin is a no-op.
	db := testDB(t)
	require.NoError(t, NewAuthzGormPlugin().Initialize(db))

	var dest []map[string]any
	sql := db.WithContext(context.Background()).Table("certificates").Find(&dest).Statement.SQL.String()

	assert.NotContains(t, strings.ToUpper(sql), "JOIN")
	assert.NotContains(t, strings.ToUpper(sql), "WHERE")
}

func TestAuthzGormPlugin_SkipsIfAuthzQueryEmpty(t *testing.T) {
	// Empty string value → plugin is a no-op.
	db := testDB(t)
	require.NoError(t, NewAuthzGormPlugin().Initialize(db))

	ctx := context.WithValue(context.Background(), authzsdk.AuthzQueryKey, "")
	var dest []map[string]any
	sql := db.WithContext(ctx).Table("certificates").Find(&dest).Statement.SQL.String()

	assert.NotContains(t, strings.ToUpper(sql), "JOIN")
	assert.NotContains(t, strings.ToUpper(sql), "WHERE")
}

func TestAuthzGormPlugin_SkipsIfAuthzQueryNotAString(t *testing.T) {
	// Wrong type for value → plugin is a no-op (type assertion fails silently).
	db := testDB(t)
	require.NoError(t, NewAuthzGormPlugin().Initialize(db))

	ctx := context.WithValue(context.Background(), authzsdk.AuthzQueryKey, 42)
	var dest []map[string]any
	sql := db.WithContext(ctx).Table("certificates").Find(&dest).Statement.SQL.String()

	assert.NotContains(t, strings.ToUpper(sql), "JOIN")
	assert.NotContains(t, strings.ToUpper(sql), "WHERE")
}

// viewTablePolicySQL is the shape the engine generates for an entity declared with a
// view table: it reads the view under the entity's canonical table name.
const viewTablePolicySQL = `SELECT * FROM ca.certificates_view AS certificates LEFT JOIN ca.grants AS j0 ON certificates.serial_number = j0.serial_number WHERE certificates.has_private_key = true AND j0.owner = 'allowed'`

func TestAuthzGormPlugin_InjectsViewTablePolicyIntoAliasedViewQuery(t *testing.T) {
	// The certificate store reads "certificates_view AS certificates". Skipping injection
	// here would return every row (fail open).
	db := testDB(t)
	require.NoError(t, NewAuthzGormPlugin().Initialize(db))
	ctx := context.WithValue(context.Background(), authzsdk.AuthzQueryKey, viewTablePolicySQL)
	var dest []map[string]any
	result := db.WithContext(ctx).Table("certificates_view AS certificates").Find(&dest)
	require.NoError(t, result.Error)
	sql := result.Statement.SQL.String()
	assert.Contains(t, sql, "LEFT JOIN ca.grants AS j0 ON certificates.serial_number = j0.serial_number")
	assert.Contains(t, sql, "certificates.has_private_key = true")
	assert.Contains(t, sql, "j0.owner = 'allowed'")
}

func TestAuthzGormPlugin_InjectsViewTablePolicyIntoCanonicalTableQuery(t *testing.T) {
	// A read of the canonical table must get the restriction too. If it names a column only
	// the view has, the database rejects the query: it fails closed instead of listing everything.
	db := testDB(t)
	require.NoError(t, NewAuthzGormPlugin().Initialize(db))
	ctx := context.WithValue(context.Background(), authzsdk.AuthzQueryKey, viewTablePolicySQL)
	var dest []map[string]any
	sql := db.WithContext(ctx).Table("certificates").Find(&dest).Statement.SQL.String()
	assert.Contains(t, sql, "certificates.has_private_key = true")
}

func TestAuthzGormPlugin_SkipsOtherEntityPolicyForAliasedViewPreload(t *testing.T) {
	// Listing CAs preloads their certificate from "certificates_view AS certificates" in the
	// same context. The ca_certificate policy must not be injected into that preload.
	db := testDB(t)
	require.NoError(t, NewAuthzGormPlugin().Initialize(db))
	authzSQL := `SELECT * FROM ca.ca_certificates WHERE ca_certificates.id = 'allowed'`
	ctx := context.WithValue(context.Background(), authzsdk.AuthzQueryKey, authzSQL)
	var dest []map[string]any
	sql := db.WithContext(ctx).Table("certificates_view AS certificates").Find(&dest).Statement.SQL.String()
	assert.NotContains(t, strings.ToUpper(sql), "WHERE")
}

func TestAuthzGormPlugin_InjectsDenyAll(t *testing.T) {
	// Deny-all filter (1 = 0) must be injected into the WHERE clause.
	db := testDB(t)
	require.NoError(t, NewAuthzGormPlugin().Initialize(db))

	authzSQL := `SELECT * FROM ca.certificates WHERE 1 = 0`
	ctx := context.WithValue(context.Background(), authzsdk.AuthzQueryKey, authzSQL)

	var dest []map[string]any
	sql := db.WithContext(ctx).Table("ca.certificates").Find(&dest).Statement.SQL.String()

	assert.Contains(t, sql, "1 = 0")
	assert.NotContains(t, strings.ToUpper(sql), "JOIN")
}

func TestAuthzGormPlugin_InjectsWildcardGrantAll(t *testing.T) {
	// Wildcard grant (1 = 1) means all rows are accessible.
	db := testDB(t)
	require.NoError(t, NewAuthzGormPlugin().Initialize(db))

	authzSQL := `SELECT * FROM ca.certificates WHERE 1 = 1`
	ctx := context.WithValue(context.Background(), authzsdk.AuthzQueryKey, authzSQL)

	var dest []map[string]any
	sql := db.WithContext(ctx).Table("ca.certificates").Find(&dest).Statement.SQL.String()

	assert.Contains(t, sql, "1 = 1")
	assert.NotContains(t, strings.ToUpper(sql), "JOIN")
}

func TestAuthzGormPlugin_InjectsSingleHopFilter(t *testing.T) {
	// One hop: devices accessible via their DMS owner.
	db := testDB(t)
	require.NoError(t, NewAuthzGormPlugin().Initialize(db))

	authzSQL := `SELECT * FROM devicemanager.devices LEFT JOIN dmsmanager.dms AS j0_0 ON devicemanager.devices.dms_owner = j0_0.id WHERE j0_0.id = 'sample-dms-01'`
	ctx := context.WithValue(context.Background(), authzsdk.AuthzQueryKey, authzSQL)

	var dest []map[string]any
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
	ctx := context.WithValue(context.Background(), authzsdk.AuthzQueryKey, authzSQL)

	var dest []map[string]any
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
	ctx := context.WithValue(context.Background(), authzsdk.AuthzQueryKey, authzSQL)

	var dest []map[string]any
	sql := db.WithContext(ctx).Table("certificates").Find(&dest).Statement.SQL.String()

	assert.Contains(t, sql, "LEFT JOIN devicemanager.devices AS j0_0 ON ca.certificates.subject_common_name = j0_0.id")
	assert.Contains(t, sql, "LEFT JOIN dmsmanager.dms AS j0_1 ON j0_0.dms_owner = j0_1.id")
	assert.Contains(t, sql, "j0_1.id = 'sample-dms-01'")
	whereAfterLastJoin(t, sql)
}

func TestAuthzGormPlugin_InjectsSingleHopFilterDeviceRevoke(t *testing.T) {
	// Filter generated by device-007 rule granting status-update on certificates:
	// single JOIN to devices, WHERE j0_0.id = 'device-007'.
	db := testDB(t)
	require.NoError(t, NewAuthzGormPlugin().Initialize(db))

	authzSQL := `SELECT * FROM ca.certificates LEFT JOIN devicemanager.devices AS j0_0 ON ca.certificates.subject_common_name = j0_0.id WHERE j0_0.id = 'device-007'`
	ctx := context.WithValue(context.Background(), authzsdk.AuthzQueryKey, authzSQL)

	var dest []map[string]any
	sql := db.WithContext(ctx).Table("certificates").Find(&dest).Statement.SQL.String()

	assert.Contains(t, sql, "LEFT JOIN devicemanager.devices AS j0_0 ON ca.certificates.subject_common_name = j0_0.id")
	assert.Contains(t, sql, "j0_0.id = 'device-007'")
	whereAfterLastJoin(t, sql)
}

func TestAuthzGormPlugin_AppliesEngineGeneratedPolicyToAliasedViewQuery(t *testing.T) {
	// Contract between the engine and the plugin: the FullSQL the engine really generates
	// for an entity read through a view table must reach the query the certificate store
	// issues ("certificates_view AS certificates"). If the engine's FROM alias, its column
	// qualifier or the plugin's table matching drift apart, the plugin stops injecting the
	// policy and the listing is no longer restricted (fail open).
	schemas := engine.NewSchemaRegistry()
	require.NoError(t, schemas.Load("../../pki.json", "pki"))
	policies := engine.NewPolicyRegistry()
	require.NoError(t, policies.AddPolicy(&models.Policy{ID: "keyed", Name: "keyed", Rules: []*models.Rule{{
		Namespace: "pki", SchemaName: "ca", EntityType: "certificate", Actions: []string{"read"},
		ColumnFilters: []models.ColumnFilter{{Column: "has_private_key", Type: "bool", Operator: "eq", Value: true}},
		Relations:     []models.RelationRule{{ToSchemaName: "ca", ToEntityType: "ca_certificate", To: "ca.ca_certificate", Via: "serial_number", Actions: []string{"read"}}},
	}}}))
	fg, err := engine.NewFilterGenerator(schemas, policies)
	require.NoError(t, err)

	filter, err := fg.GenerateListFilter("read", "ca", "certificate")
	require.NoError(t, err)
	require.NotEmpty(t, filter.Conditions)

	db := testDB(t)
	require.NoError(t, NewAuthzGormPlugin().Initialize(db))
	ctx := context.WithValue(context.Background(), authzsdk.AuthzQueryKey, filter.FullSQL)
	var dest []map[string]any
	result := db.WithContext(ctx).Table("certificates_view AS certificates").Find(&dest)
	require.NoError(t, result.Error)
	sql := result.Statement.SQL.String()

	for _, join := range filter.Joins {
		assert.Contains(t, sql, join)
	}
	assert.Contains(t, sql, "WHERE "+strings.Join(filter.Conditions, " AND "))
	// Column references use the alias; the physical relation is not in scope under the alias,
	// so a schema-qualified reference would make the database reject the query.
	assert.NotContains(t, sql, "ca.certificates.")
}
