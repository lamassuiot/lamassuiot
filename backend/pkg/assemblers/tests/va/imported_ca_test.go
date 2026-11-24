package va

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/require"
)

// ImportCA raises ca.import, not ca.create. An imported CA whose key the KMS holds can sign CRLs, so it gets its
// CRL settings and its first CRL like any created CA; one imported without a key gets none.
func TestImportedCAGetsCRLSettingsOnlyWithAKey(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSvc := serverTest.CA.Service
	profileID := issuanceProfileForImport(t)

	t.Run("a CA imported with its private key", func(t *testing.T) {
		cert, key := selfSignedCAForVA(t, "imported-with-key")

		ca, err := caSvc.ImportCA(ctx, services.ImportCAInput{
			ProfileID:     profileID,
			Key:           key,
			CACertificate: (*models.X509Certificate)(cert),
		})
		require.NoError(t, err)
		require.Equal(t, models.CertificateTypeImportedWithKey, ca.Certificate.Type)

		settings := waitForInitialCRL(t, ca.ID)
		require.Equal(t, ca.Certificate.SerialNumber, settings.Options.SignerSerialNumber)
		requireCRLIssuedBy(t, ca)
	})

	t.Run("a CA imported whose key the KMS already holds", func(t *testing.T) {
		cert, key := selfSignedCAForVA(t, "imported-key-already-in-kms")
		_, err := serverTest.KMS.Service.ImportKey(ctx, services.ImportKeyInput{
			PrivateKey: key,
			Name:       "imported-key-already-in-kms",
		})
		require.NoError(t, err)

		ca, err := caSvc.ImportCA(ctx, services.ImportCAInput{
			ProfileID:     profileID,
			CACertificate: (*models.X509Certificate)(cert),
		})
		require.NoError(t, err)
		require.NotEmpty(t, ca.Certificate.KeyID, "the import must have found the key in the KMS")

		settings := waitForInitialCRL(t, ca.ID)
		require.Equal(t, ca.Certificate.SerialNumber, settings.Options.SignerSerialNumber)
		requireCRLIssuedBy(t, ca)
	})

	t.Run("a CA imported without a key gets no CRL settings", func(t *testing.T) {
		cert, _ := selfSignedCAForVA(t, "imported-without-key")

		ca, err := caSvc.ImportCA(ctx, services.ImportCAInput{
			ProfileID:     profileID,
			CACertificate: (*models.X509Certificate)(cert),
		})
		require.NoError(t, err)
		require.Equal(t, models.CertificateTypeImportedWithoutKey, ca.Certificate.Type)

		// The settings of the CAs above were created well within this window, so the VA has had the time to
		// handle this import too: finding none here means none are ever created.
		time.Sleep(15 * time.Second)
		_, err = serverTest.VA.CRLService.GetCRLSettings(ctx, services.GetCRLSettingsInput{CAID: ca.ID})
		require.ErrorIs(t, err, errs.ErrCRLSettingsNotFound)
	})
}

func issuanceProfileForImport(t *testing.T) string {
	t.Helper()
	profile, err := serverTest.CA.Service.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)},
		},
	})
	require.NoError(t, err)
	return profile.ID
}

func selfSignedCAForVA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert, key
}
