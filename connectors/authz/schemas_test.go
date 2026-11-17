package authz

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/engine"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/models"
	"github.com/stretchr/testify/require"
)

// The policy builder offers every relation the schema declares, so each one must yield a policy the
// server accepts. A relation that the validator always rejects (such as a self-reference, which
// validateSimpleRelationPaths treats as a repeated vertex) is an option no one can save.
func TestPKISchemaRelationsYieldValidPolicies(t *testing.T) {
	registry, err := PKISchemas()
	require.NoError(t, err)

	for _, schema := range registry.GetAll() {
		for _, rel := range schema.Relations {
			var target *engine.SchemaDefinition
			for _, candidate := range registry.GetAll() {
				if candidate.EntityType == rel.TargetEntity {
					target = candidate
				}
			}
			require.NotNil(t, target, "%s.%s: unknown target entity %q", schema.SchemaName, schema.EntityType, rel.TargetEntity)

			policy := &models.Policy{
				ID:   "relation-check",
				Name: "relation check",
				Rules: []*models.Rule{{
					Namespace:  "pki",
					SchemaName: schema.SchemaName,
					EntityType: schema.EntityType,
					Actions:    []string{"read"},
					Relations: []models.RelationRule{{
						ToSchemaName: target.SchemaName,
						ToEntityType: target.EntityType,
						Via:          rel.ForeignKey,
						Actions:      []string{"read"},
					}},
				}},
			}
			require.NoError(t, engine.ValidatePolicyStruct(policy), "%s.%s relation %q", schema.SchemaName, schema.EntityType, rel.Name)
		}
	}
}

func TestPKISchemasLoadsEmbeddedSchema(t *testing.T) {
	registry, err := PKISchemas()
	if err != nil {
		t.Fatalf("load embedded PKI schemas: %v", err)
	}

	if _, err := registry.GetBySchemaEntity("ca", "certificate"); err != nil {
		t.Fatalf("get certificate schema: %v", err)
	}
}

func TestCRLSettingsColumnContract(t *testing.T) {
	registry, err := PKISchemas()
	require.NoError(t, err)
	settings, err := registry.GetBySchemaEntity("va", "crl_settings")
	require.NoError(t, err)
	require.Equal(t, []string{"ca_id"}, settings.PrimaryKeys)
	require.Contains(t, settings.AtomicActions, "delete", "archived settings are purged with the delete action")
	for _, column := range []string{"ca_id", "status", "legacy_ski", "signer_serial_number", "signer_engine_id", "signer_key_id"} {
		require.NotNil(t, settings.GetFilterableField(column), column)
	}
	require.Nil(t, settings.GetFilterableField("crl_signer_certificate_serial_number"))

	// Filters and relation joins are emitted as raw SQL on these columns, so a name the table does not have makes
	// every request under a policy that uses it fail.
	columns := crlSettingsMigrationColumns(t)
	for _, f := range settings.Filterable {
		require.Contains(t, columns, f.Column, "filterable column")
	}
	require.NotEmpty(t, settings.Relations)
	for _, rel := range settings.Relations {
		require.Contains(t, columns, rel.ForeignKey, "foreign key of relation %s", rel.Name)
	}

	_, err = registry.GetBySchemaEntity("va", "va_role")
	require.Error(t, err, "the va_role entity is gone")
}

// crlSettingsMigrationColumns returns the columns of the crl_settings table as the VA migration creates it.
func crlSettingsMigrationColumns(t *testing.T) []string {
	t.Helper()
	sql, err := os.ReadFile("../../engines/storage/postgres/migrations/va/20261111120000_crl_settings.sql")
	require.NoError(t, err)
	table := regexp.MustCompile(`(?s)CREATE TABLE crl_settings \((.*?)\n \);`).FindSubmatch(sql)
	require.NotNil(t, table, "CREATE TABLE crl_settings not found in the migration")
	var columns []string
	for _, line := range strings.Split(string(table[1]), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] == "CONSTRAINT" {
			continue
		}
		columns = append(columns, fields[0])
	}
	require.Contains(t, columns, "ca_id")
	return columns
}
