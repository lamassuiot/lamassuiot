package ca

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/require"
)

// Importing a CA finds the CAs it issued by their issuer, so every stored certificate records it.
func TestCertificatesStoreTheirIssuer(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSvc := serverTest.CA.Service
	profile := newBindingsProfile(t)

	storedIssuerCN := func(t *testing.T, serial string) string {
		t.Helper()
		cert, err := caSvc.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{SerialNumber: serial})
		require.NoError(t, err)
		return cert.Issuer.CommonName
	}

	root := createBindingsCA(t, "issuer-root", profile.ID, "")
	t.Run("root CA", func(t *testing.T) {
		require.Equal(t, "issuer-root", storedIssuerCN(t, root.Certificate.SerialNumber))
	})

	t.Run("subordinate CA", func(t *testing.T) {
		sub, err := caSvc.CreateCA(ctx, services.CreateCAInput{
			ParentID:     root.ID,
			KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256},
			Subject:      models.Subject{CommonName: "issuer-sub"},
			CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(12 * time.Hour)},
			ProfileID:    profile.ID,
		})
		require.NoError(t, err)
		require.Equal(t, "issuer-root", storedIssuerCN(t, sub.Certificate.SerialNumber))
	})

	t.Run("imported certificate", func(t *testing.T) {
		x509Cert, _ := selfSignedCAWithForeignSKI(t, "issuer-imported")
		cert, err := caSvc.ImportCertificate(ctx, services.ImportCertificateInput{Certificate: (*models.X509Certificate)(x509Cert)})
		require.NoError(t, err)
		require.Equal(t, "issuer-imported", storedIssuerCN(t, cert.SerialNumber))
	})
}
