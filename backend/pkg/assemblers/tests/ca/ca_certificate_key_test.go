package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/require"
)

func TestGetCertificateKey(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSvc := serverTest.CA.Service

	profile, err := caSvc.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)}},
	})
	require.NoError(t, err)

	created, err := caSvc.CreateCA(ctx, services.CreateCAInput{
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256},
		Subject:      models.Subject{CommonName: "certificate-key-created"},
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(24 * time.Hour)},
		ProfileID:    profile.ID,
		EngineID:     otherEngine,
	})
	require.NoError(t, err)

	importedCert, importedKey := selfSignedCAWithForeignSKI(t, "certificate-key-imported")
	imported, err := caSvc.ImportCA(ctx, services.ImportCAInput{ProfileID: profile.ID, Key: importedKey, CACertificate: (*models.X509Certificate)(importedCert)})
	require.NoError(t, err)

	externalKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "certificate-key-external"}, externalKey)
	require.NoError(t, err)
	external, err := caSvc.SignCertificate(ctx, services.SignCertificateInput{CAID: created.ID, CertRequest: (*models.X509CertificateRequest)(csr), IssuanceProfileID: profile.ID})
	require.NoError(t, err)

	// Imported without key; the key reaches the KMS afterwards, but nothing links it to the certificate.
	unlinkedCert, unlinkedKey := selfSignedCAWithForeignSKI(t, "certificate-key-unlinked")
	unlinked, err := caSvc.ImportCA(ctx, services.ImportCAInput{CACertificate: (*models.X509Certificate)(unlinkedCert)})
	require.NoError(t, err)
	importKeyInto(t, unlinkedKey, defaultEngine)

	requireKeyOf := func(t *testing.T, cert *x509.Certificate, engineID string, got *models.CertificateKey) {
		t.Helper()
		require.NotNil(t, got)
		require.Equal(t, kmsKeyIDOf(t, cert.PublicKey), got.KeyID)
		require.Equal(t, engineID, got.EngineID)
		require.Equal(t, "pkcs11:token-id="+engineID+";id="+got.KeyID+";type=private", got.PKCS11URI)
		require.Equal(t, "ECDSA", got.Algorithm)
		require.Equal(t, 256, got.Size)
		pemBytes, err := base64.StdEncoding.DecodeString(got.PublicKey)
		require.NoError(t, err)
		pub, err := chelpers.ParsePublicKey(pemBytes)
		require.NoError(t, err)
		require.True(t, cert.PublicKey.(*ecdsa.PublicKey).Equal(pub))
	}

	for name, svc := range map[string]services.CAService{"service": caSvc, "http": serverTest.CA.HttpCASDK} {
		t.Run(name, func(t *testing.T) {
			t.Run("key of a CA created in a given engine", func(t *testing.T) {
				got, err := svc.GetCertificateKey(ctx, services.GetCertificateKeyInput{SerialNumber: created.Certificate.SerialNumber})
				require.NoError(t, err)
				requireKeyOf(t, (*x509.Certificate)(created.Certificate.Certificate), otherEngine, got)
			})

			t.Run("key of a CA imported with a foreign SKI", func(t *testing.T) {
				got, err := svc.GetCertificateKey(ctx, services.GetCertificateKeyInput{SerialNumber: imported.Certificate.SerialNumber})
				require.NoError(t, err)
				requireKeyOf(t, importedCert, defaultEngine, got)
			})

			t.Run("certificate whose key is outside the KMS", func(t *testing.T) {
				_, err := svc.GetCertificateKey(ctx, services.GetCertificateKeyInput{SerialNumber: external.SerialNumber})
				require.ErrorIs(t, err, errs.ErrKeyNotFound)
			})

			t.Run("certificate not linked to the key the KMS holds", func(t *testing.T) {
				_, err := svc.GetCertificateKey(ctx, services.GetCertificateKeyInput{SerialNumber: unlinked.Certificate.SerialNumber})
				require.ErrorIs(t, err, errs.ErrKeyNotFound)
			})

			t.Run("unknown certificate", func(t *testing.T) {
				_, err := svc.GetCertificateKey(ctx, services.GetCertificateKeyInput{SerialNumber: "00-11-22"})
				require.ErrorIs(t, err, errs.ErrCertificateNotFound)
			})
		})
	}
}
