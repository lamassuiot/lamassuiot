package authz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVARoleSignerColumnContract(t *testing.T) {
	registry, err := PKISchemas()
	require.NoError(t, err)
	role, err := registry.GetBySchemaEntity("va", "va_role")
	require.NoError(t, err)
	require.NotNil(t, role.GetFilterableField("crl_signer_certificate_serial_number"))
	require.Nil(t, role.GetFilterableField("crl_subject_key_id_signer"))
}
