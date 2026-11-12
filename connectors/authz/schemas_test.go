package authz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

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
