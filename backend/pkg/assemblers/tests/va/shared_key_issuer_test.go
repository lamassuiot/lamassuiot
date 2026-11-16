package va

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/assemblers/tests"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/require"
)

// CAs sharing a key have one CRL settings each. The CRL of a CA is issued by that CA, and it stays so after the
// CA is reissued.
func TestCRLOfCAsSharingAKeyIsIssuedByEachCA(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSvc := serverTest.CA.Service
	owner, err := initCAForVA(caSvc)
	require.NoError(t, err)
	settings := waitForInitialCRL(t, owner.ID)
	require.Equal(t, owner.Certificate.SerialNumber, settings.Options.SignerSerialNumber)

	// The backend assigns a separate ID even though both CAs share a key.
	shared, err := caSvc.CreateCA(ctx, services.CreateCAInput{
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048, KeyID: "pkcs11:token-id=" + owner.Certificate.EngineID + ";id=" + owner.Certificate.KeyID + ";type=private"},
		Subject:      models.Subject{CommonName: "Shared key CA"},
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(24 * time.Hour)},
		ProfileID:    owner.ProfileID,
	})
	require.NoError(t, err)
	require.Equal(t, owner.Certificate.SubjectKeyID, shared.Certificate.SubjectKeyID, "the CAs share the SKI")
	sharedSettings := waitForInitialCRL(t, shared.ID)
	require.Equal(t, shared.Certificate.SerialNumber, sharedSettings.Options.SignerSerialNumber)

	requireCRLIssuedBy(t, owner)
	requireCRLIssuedBy(t, shared)

	// After a reissue the settings move to the owner's new certificate, and the CRL is still issued by the owner.
	reissued, err := caSvc.ReissueCA(ctx, services.ReissueCAInput{CAID: owner.ID})
	require.NoError(t, err)
	waitForCRLSettings(t, owner.ID, func(r *models.CRLSettings) bool {
		return r.Options.SignerSerialNumber == reissued.Certificate.SerialNumber
	})
	requireCRLIssuedBy(t, owner)
}

// The CA that shares the key of another one raises ca.create too: each CA gets its own settings, and a retried event
// keeps the settings instead of failing or resetting the CRL.
func TestInitCRLSettingsKeepsExistingSettings(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	owner, err := initCAForVA(serverTest.CA.Service)
	require.NoError(t, err)
	settings := waitForInitialCRL(t, owner.ID)

	again, err := serverTest.VA.CRLService.InitCRLSettings(ctx, owner.ID)
	require.NoError(t, err)
	require.Equal(t, settings.Options.SignerSerialNumber, again.Options.SignerSerialNumber)
	require.Equal(t, settings.LatestCRL.Version.String(), again.LatestCRL.Version.String(), "the existing CRL must not be reset")
}

func waitForInitialCRL(t *testing.T, caID string) *models.CRLSettings {
	t.Helper()
	var settings *models.CRLSettings
	require.NoError(t, tests.SleepRetry(5, 3*time.Second, func() error {
		var err error
		settings, err = serverTest.VA.CRLService.GetCRLSettings(context.Background(), services.GetCRLSettingsInput{CAID: caID})
		if err != nil {
			return err
		}
		if settings.LatestCRL.Version.Int == nil || settings.LatestCRL.Version.Int.Sign() == 0 {
			return errs.ErrCRLSettingsNotFound
		}
		return nil
	}))
	return settings
}

func requireCRLIssuedBy(t *testing.T, ca *models.CACertificate) {
	t.Helper()
	crl, err := serverTest.VA.CRLService.CalculateCRL(context.Background(), services.CalculateCRLInput{CAID: ca.ID})
	require.NoError(t, err)
	caCert := (*x509.Certificate)(ca.Certificate.Certificate)
	require.Equal(t, caCert.RawSubject, crl.RawIssuer)
	require.NoError(t, crl.CheckSignatureFrom(caCert))
}
