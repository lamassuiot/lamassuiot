package helpers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestFormatHexWithColons(t *testing.T) {
	require.Equal(t, "00:AB:FF", FormatHexWithColons([]byte{0, 0xab, 0xff}))
	require.Equal(t, "", FormatHexWithColons(nil))
}

func TestGetSubjectKeyIDUsesCertificateSKI(t *testing.T) {
	cert := &x509.Certificate{SubjectKeyId: []byte{0x01, 0xab}}
	got, err := GetSubjectKeyID(nil, logrus.NewEntry(logrus.New()), cert)
	require.NoError(t, err)
	require.Equal(t, "01ab", got)
}

func TestGetSubjectKeyIDDerivesPublicKeyDigest(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	cert := &x509.Certificate{PublicKey: &key.PublicKey}
	got, err := GetSubjectKeyID(nil, logrus.NewEntry(logrus.New()), cert)
	require.NoError(t, err)
	require.Len(t, got, 64)

	cert = &x509.Certificate{PublicKey: struct{}{}}
	_, err = GetSubjectKeyID(nil, logrus.NewEntry(logrus.New()), cert)
	require.Error(t, err)
}
