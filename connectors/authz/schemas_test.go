package authz

import (
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
	for _, column := range []string{"ca_id", "status", "legacy_ski", "signer_serial_number"} {
		require.NotNil(t, settings.GetFilterableField(column), column)
	}
	require.Nil(t, settings.GetFilterableField("crl_signer_certificate_serial_number"))

	_, err = registry.GetBySchemaEntity("va", "va_role")
	require.Error(t, err, "the va_role entity is gone")
}
