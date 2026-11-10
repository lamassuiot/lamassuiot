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

// CAs sharing a key share the VA Role of their SKI. The CRL is issued by the CA of the Role's signer, not by
// whichever of them a lookup by SKI returns first.
func TestCRLOfCAsSharingAKeyIsIssuedByTheCAOfTheRoleSigner(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSvc := serverTest.CA.Service
	owner, err := initCAForVA(caSvc)
	require.NoError(t, err)
	role := waitForInitialCRL(t, owner.Certificate.SubjectKeyID)
	require.Equal(t, owner.Certificate.SerialNumber, role.CRLOptions.SignerCertificateSerialNumber)

	// Its ID sorts before the owner's, so an unordered lookup by SKI finds it first.
	_, err = caSvc.CreateCA(ctx, services.CreateCAInput{
		ID:           "000-shared-key",
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048, KeyID: "pkcs11:token-id=" + owner.Certificate.EngineID + ";id=" + owner.Certificate.KeyID + ";type=private"},
		Subject:      models.Subject{CommonName: "Shared key CA"},
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(24 * time.Hour)},
		ProfileID:    owner.ProfileID,
	})
	require.NoError(t, err)

	requireCRLIssuedBy(t, role.CASubjectKeyID, owner)

	// After a reissue the Role still references the owner's superseded certificate: same subject and key.
	_, err = caSvc.ReissueCA(ctx, services.ReissueCAInput{CAID: owner.ID})
	require.NoError(t, err)
	requireCRLIssuedBy(t, role.CASubjectKeyID, owner)
}

// The CA that shares the key of another one raises ca.create too: its VA Role already exists, so initializing
// it again keeps the Role instead of failing and having the event retried.
func TestInitCRLRoleKeepsTheRoleOfACAWithTheSameKey(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	owner, err := initCAForVA(serverTest.CA.Service)
	require.NoError(t, err)
	role := waitForInitialCRL(t, owner.Certificate.SubjectKeyID)

	again, err := serverTest.VA.CRLService.InitCRLRole(ctx, owner.Certificate.SubjectKeyID)
	require.NoError(t, err)
	require.Equal(t, role.CRLOptions.SignerCertificateSerialNumber, again.CRLOptions.SignerCertificateSerialNumber)
	require.Equal(t, role.LatestCRL.Version.String(), again.LatestCRL.Version.String(), "the existing CRL must not be reset")
}

func waitForInitialCRL(t *testing.T, ski string) *models.VARole {
	t.Helper()
	var role *models.VARole
	require.NoError(t, tests.SleepRetry(5, 3*time.Second, func() error {
		var err error
		role, err = serverTest.VA.CRLService.GetVARole(context.Background(), services.GetVARoleInput{CASubjectKeyID: ski})
		if err != nil {
			return err
		}
		if role.LatestCRL.Version.Int == nil || role.LatestCRL.Version.Int.Sign() == 0 {
			return errs.ErrVARoleNotFound
		}
		return nil
	}))
	return role
}

func requireCRLIssuedBy(t *testing.T, ski string, ca *models.CACertificate) {
	t.Helper()
	crl, err := serverTest.VA.CRLService.CalculateCRL(context.Background(), services.CalculateCRLInput{CASubjectKeyID: ski})
	require.NoError(t, err)
	caCert := (*x509.Certificate)(ca.Certificate.Certificate)
	require.Equal(t, caCert.RawSubject, crl.RawIssuer)
	require.NoError(t, crl.CheckSignatureFrom(caCert))
}
