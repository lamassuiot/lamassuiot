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

func TestVARoleSignerColumnContract(t *testing.T) {
	registry, err := PKISchemas()
	require.NoError(t, err)
	role, err := registry.GetBySchemaEntity("va", "va_role")
	require.NoError(t, err)
	require.NotNil(t, role.GetFilterableField("crl_signer_certificate_serial_number"))
	require.Nil(t, role.GetFilterableField("crl_subject_key_id_signer"))
}
