package ca

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Certificates are stored with their issuer: importing a CA finds the CAs it issued by it.
func TestCertificatesAreStoredWithTheirIssuer(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caTest := serverTest.CA

	profile, err := caTest.Service.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)}},
	})
	require.NoError(t, err)
	newCA := func(cn, parentID string) *models.CACertificate {
		ca, err := caTest.Service.CreateCA(ctx, services.CreateCAInput{
			ParentID:     parentID,
			KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
			Subject:      models.Subject{CommonName: cn},
			CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour * 12)},
			ProfileID:    profile.ID,
		})
		require.NoError(t, err)
		return ca
	}
	storedIssuer := func(caID string) string {
		ca, err := caTest.Service.GetCAByID(ctx, services.GetCAByIDInput{CAID: caID})
		require.NoError(t, err)
		return ca.Certificate.Issuer.CommonName
	}

	root := newCA("IssuerRoot", "")
	sub := newCA("IssuerSub", root.ID)

	t.Run("CreateCA", func(t *testing.T) {
		assert.Equal(t, "IssuerRoot", storedIssuer(root.ID))
		assert.Equal(t, "IssuerRoot", storedIssuer(sub.ID))
	})

	t.Run("ReissueCA", func(t *testing.T) {
		reissued, err := caTest.Service.ReissueCA(ctx, services.ReissueCAInput{CAID: sub.ID})
		require.NoError(t, err)
		assert.Equal(t, "IssuerRoot", reissued.Certificate.Issuer.CommonName)
		assert.Equal(t, "IssuerRoot", storedIssuer(sub.ID))
	})

	t.Run("ImportCertificate", func(t *testing.T) {
		cert, _, err := chelpers.GenerateSelfSignedCA(x509.RSA, time.Hour, "ImportedIssuer")
		require.NoError(t, err)
		imported, err := caTest.Service.ImportCertificate(ctx, services.ImportCertificateInput{Certificate: (*models.X509Certificate)(cert)})
		require.NoError(t, err)

		stored, err := caTest.Service.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{SerialNumber: imported.SerialNumber})
		require.NoError(t, err)
		assert.Equal(t, "ImportedIssuer", stored.Issuer.CommonName)
	})
}
