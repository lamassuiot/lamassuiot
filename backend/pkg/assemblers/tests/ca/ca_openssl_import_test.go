package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/require"
)

func opensslCA(t *testing.T) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	cert, err := chelpers.ParseCertificate(opensslCACertPEM)
	require.NoError(t, err)
	key, err := chelpers.ParsePrivateKey([]byte(opensslCAKeyPEM))
	require.NoError(t, err)
	require.Equal(t, opensslCASKI, hex.EncodeToString(cert.SubjectKeyId), "fixture precondition: the OpenSSL SKI")
	require.NotEqual(t, opensslCASKI, opensslCAKeyID)
	return cert, key.(crypto.Signer)
}

// requireIssues signs a certificate with the CA and checks it chains to the CA certificate.
func requireIssues(t *testing.T, caID, profileID string, caCert *x509.Certificate) {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "openssl-ca-leaf"}, leafKey)
	require.NoError(t, err)
	leaf, err := serverTest.CA.HttpCASDK.SignCertificate(context.Background(), services.SignCertificateInput{
		CAID: caID, CertRequest: (*models.X509CertificateRequest)(csr), IssuanceProfileID: profileID,
	})
	require.NoError(t, err)
	require.NoError(t, (*x509.Certificate)(leaf.Certificate).CheckSignatureFrom(caCert))
}

// A CA issued by OpenSSL, whose SKI is not the key ID, works through its whole life once imported.
func TestOpenSSLCAImportedWithItsKey(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSDK := serverTest.CA.HttpCASDK
	caCert, caKey := opensslCA(t)
	profile := newBindingsProfile(t)

	ca, err := caSDK.ImportCA(ctx, services.ImportCAInput{ProfileID: profile.ID, Key: caKey, CACertificate: (*models.X509Certificate)(caCert)})
	require.NoError(t, err)
	require.Equal(t, opensslCAKeyID, ca.Certificate.KeyID)
	require.Equal(t, []string{ca.Certificate.SerialNumber}, boundSerials(t, &ca.Certificate))

	requireIssues(t, ca.ID, profile.ID, caCert)

	key, err := caSDK.GetCertificateKey(ctx, services.GetCertificateKeyInput{SerialNumber: ca.Certificate.SerialNumber})
	require.NoError(t, err)
	require.Equal(t, opensslCAKeyID, key.KeyID)

	revokeCA(t, serverTest.CA.Service, ca.ID)
	require.NoError(t, caSDK.DeleteCA(ctx, services.DeleteCAInput{CAID: ca.ID}))
	_, err = serverTest.KMS.Service.GetKey(ctx, services.GetKeyInput{Identifier: keyURI(&ca.Certificate)})
	require.ErrorIs(t, err, errs.ErrKeyNotFound, "the key of a deleted CA no other certificate uses is deleted")
}

func TestOpenSSLCAImportedWithoutItsKeyFindsItInTheKMS(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caCert, caKey := opensslCA(t)
	profile := newBindingsProfile(t)

	_, err := serverTest.KMS.Service.ImportKey(ctx, services.ImportKeyInput{PrivateKey: caKey, EngineID: defaultEngine, Name: "openssl-ca-key"})
	require.NoError(t, err)

	ca, err := serverTest.CA.HttpCASDK.ImportCA(ctx, services.ImportCAInput{ProfileID: profile.ID, CACertificate: (*models.X509Certificate)(caCert)})
	require.NoError(t, err)
	require.Equal(t, models.CertificateTypeManaged, ca.Certificate.Type)
	require.Equal(t, opensslCAKeyID, ca.Certificate.KeyID)
	require.Equal(t, []string{ca.Certificate.SerialNumber}, boundSerials(t, &ca.Certificate))

	requireIssues(t, ca.ID, profile.ID, caCert)
}
