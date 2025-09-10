package helpers

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetSubjectKeyID_WithSKIDPresent(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	skid := []byte{0x01, 0x02, 0x03, 0x04}
	cert := &x509.Certificate{
		SubjectKeyId: skid,
		Subject:      pkixNameWithCN("test-cn"),
	}
	result, err := GetSubjectKeyID(logger, cert)
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(skid), result)
}

func TestGetSubjectKeyID_WithoutSKID_GeneratesFromPublicKey(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	expected := "ea9584789615e826a85b31d9b6e8a9af1a9ebb0cc3f4ee885b4910387b4556fa"

	cert := &x509.Certificate{
		SubjectKeyId: nil,
		Subject:      pkixNameWithCN("test-cn"),
		PublicKey:    &rsa.PublicKey{N: big.NewInt(12345), E: 65537},
	}
	result, err := GetSubjectKeyID(logger, cert)
	require.NoError(t, err)
	assert.Equal(t, expected, result)
}

func TestGetSubjectKeyID_WithoutSKIDAndPublicKey(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())

	cert := &x509.Certificate{
		SubjectKeyId: nil,
		Subject:      pkixNameWithCN("test-cn"),
		PublicKey:    nil,
	}
	result, err := GetSubjectKeyID(logger, cert)
	require.Error(t, err)
	assert.Empty(t, result)
}

// Helper to create pkix.Name with CommonName
func pkixNameWithCN(cn string) pkix.Name {
	return pkix.Name{CommonName: cn}
}
