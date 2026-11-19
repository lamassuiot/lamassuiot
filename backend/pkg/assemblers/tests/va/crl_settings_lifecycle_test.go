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
	"golang.org/x/crypto/ocsp"
)

func waitForStatus(t *testing.T, caID string, status models.CRLSettingsStatus) *models.CRLSettings {
	t.Helper()
	return waitForCRLSettings(t, caID, func(s *models.CRLSettings) bool { return s.Status == status })
}

// kmsKeyExists tells whether the KMS still holds the key of a certificate.
func kmsKeyExists(t *testing.T, cert models.Certificate) bool {
	t.Helper()
	var n int64
	require.NoError(t, vaSchemaDB(t).Raw(`SELECT count(*) FROM kms.kms_keys WHERE engine_id = ? AND key_id = ?`, cert.EngineID, cert.KeyID).Scan(&n).Error)
	return n > 0
}

func signerKeyColumns(t *testing.T, caID string) (engineID, keyID *string) {
	t.Helper()
	row := struct {
		EngineID *string `gorm:"column:signer_engine_id"`
		KeyID    *string `gorm:"column:signer_key_id"`
	}{}
	require.NoError(t, vaSchemaDB(t).Raw(`SELECT signer_engine_id, signer_key_id FROM crl_settings WHERE ca_id = ?`, caID).Scan(&row).Error)
	return row.EngineID, row.KeyID
}

// The whole lifecycle: revoking the CA issues its final CRL, valid until the CA expires, and stops retaining its key;
// deleting the CA then deletes the key and archives the settings, whose last CRL is still served until they are purged.
func TestRevokedCAGetsAFinalCRLAndCanThenBeDeleted(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSvc := serverTest.CA.Service
	ca, err := initCAForVA(caSvc)
	require.NoError(t, err)
	waitForInitialCRL(t, ca.ID)
	engineID, keyID := signerKeyColumns(t, ca.ID)
	require.Equal(t, ca.Certificate.KeyID, *keyID, "ACTIVE settings retain the key of their signer")
	require.Equal(t, ca.Certificate.EngineID, *engineID)
	cert, err := generateCertificate(caSvc)
	require.NoError(t, err)

	_, err = caSvc.UpdateCAStatus(ctx, services.UpdateCAStatusInput{CAID: ca.ID, Status: models.StatusRevoked, RevocationReason: ocsp.KeyCompromise})
	require.NoError(t, err)
	final := waitForStatus(t, ca.ID, models.CRLSettingsFinal)
	engineID, keyID = signerKeyColumns(t, ca.ID)
	require.Nil(t, engineID)
	require.Nil(t, keyID)

	crl, err := serverTest.VA.HttpVASDK.GetCRL(ctx, services.GetCRLResponseInput{ID: ca.ID})
	require.NoError(t, err)
	require.Equal(t, final.LatestCRL.Version.String(), crl.Number.String())
	require.True(t, crl.NextUpdate.Equal(ca.Certificate.ValidTo.Truncate(time.Second)), "final CRL until %s, got %s", ca.Certificate.ValidTo, crl.NextUpdate)
	require.Contains(t, revokedSerials(crl), cert.SerialNumber, "the certificates revoked with the CA are in its final CRL")

	require.NoError(t, caSvc.DeleteCA(ctx, services.DeleteCAInput{CAID: ca.ID}))
	require.False(t, kmsKeyExists(t, ca.Certificate), "the key is deleted once the final CRL is issued")
	waitForStatus(t, ca.ID, models.CRLSettingsArchived)
	archived, err := serverTest.VA.HttpVASDK.GetCRL(ctx, services.GetCRLResponseInput{ID: ca.ID})
	require.NoError(t, err)
	require.Equal(t, crl.Raw, archived.Raw, "the final CRL is still served")

	require.NoError(t, serverTest.VA.HttpVASDK.DeleteCRLSettings(ctx, services.DeleteCRLSettingsInput{CAID: ca.ID}))
	_, err = serverTest.VA.HttpVASDK.GetCRLSettingsByID(ctx, services.GetCRLSettingsInput{CAID: ca.ID})
	require.ErrorIs(t, err, errs.ErrCRLSettingsNotFound)
}

// An expired CA gets no final CRL: one signed by an expired CA is not trusted.
func TestExpiredCAGoesFinalWithoutACRL(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ca, err := initCAForVA(serverTest.CA.Service)
	require.NoError(t, err)
	initial := waitForInitialCRL(t, ca.ID)

	_, err = serverTest.CA.Service.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{CAID: ca.ID, Status: models.StatusExpired})
	require.NoError(t, err)
	final := waitForStatus(t, ca.ID, models.CRLSettingsFinal)
	require.Equal(t, initial.LatestCRL.Version.String(), final.LatestCRL.Version.String())
	require.NoError(t, serverTest.CA.Service.DeleteCA(context.Background(), services.DeleteCAInput{CAID: ca.ID}))
}

// A hold is reversible, so the CA keeps signing CRLs and its key: it cannot be deleted, and nothing changes. The CA is
// a subordinate: putting a root on hold also revokes its own self-issued certificate (a separate, existing issue).
func TestCAOnHoldCannotBeDeleted(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSvc := serverTest.CA.Service
	root, err := initCAForVA(caSvc)
	require.NoError(t, err)
	ca, err := caSvc.CreateCA(ctx, services.CreateCAInput{
		ParentID:     root.ID,
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256},
		Subject:      models.Subject{CommonName: "Subordinate on hold"},
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(12 * time.Hour)},
		ProfileID:    root.ProfileID,
	})
	require.NoError(t, err)
	waitForInitialCRL(t, ca.ID)
	DefaultCAID = ca.ID
	cert, err := generateCertificate(caSvc)
	require.NoError(t, err)

	_, err = caSvc.UpdateCAStatus(ctx, services.UpdateCAStatusInput{CAID: ca.ID, Status: models.StatusRevoked, RevocationReason: ocsp.CertificateHold})
	require.NoError(t, err)

	err = caSvc.DeleteCA(ctx, services.DeleteCAInput{CAID: ca.ID})
	require.ErrorIs(t, err, errs.ErrCAFinalCRLPending)
	require.Contains(t, err.Error(), "revoke it permanently")
	require.ErrorIs(t, serverTest.CA.HttpCASDK.DeleteCA(ctx, services.DeleteCAInput{CAID: ca.ID}), errs.ErrCAFinalCRLPending, "409 through the API")

	_, err = caSvc.GetCAByID(ctx, services.GetCAByIDInput{CAID: ca.ID})
	require.NoError(t, err, "the CA is not deleted")
	require.True(t, kmsKeyExists(t, ca.Certificate), "nor its key")
	stored, err := caSvc.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{SerialNumber: cert.SerialNumber})
	require.NoError(t, err)
	require.Equal(t, models.StatusRevoked, stored.Status, "revoked along with the CA")
	settings, err := serverTest.VA.CRLService.GetCRLSettings(ctx, services.GetCRLSettingsInput{CAID: ca.ID})
	require.NoError(t, err)
	require.Equal(t, models.CRLSettingsActive, settings.Status)
}

// UpdateCAStatus publishes no certificate event for the certificate of a subordinate CA: the VA regenerates the CRL of
// its parent itself.
func TestRevokedSubordinateCAIsInTheCRLOfItsParent(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSvc := serverTest.CA.Service
	root, err := initCAForVA(caSvc)
	require.NoError(t, err)
	waitForInitialCRL(t, root.ID)
	sub, err := caSvc.CreateCA(ctx, services.CreateCAInput{
		ParentID:     root.ID,
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256},
		Subject:      models.Subject{CommonName: "Subordinate"},
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(12 * time.Hour)},
		ProfileID:    root.ProfileID,
	})
	require.NoError(t, err)
	waitForInitialCRL(t, sub.ID)

	_, err = caSvc.UpdateCAStatus(ctx, services.UpdateCAStatusInput{CAID: sub.ID, Status: models.StatusRevoked, RevocationReason: ocsp.KeyCompromise})
	require.NoError(t, err)
	require.NoError(t, tests.SleepRetry(5, 3*time.Second, func() error {
		crl, err := serverTest.VA.HttpVASDK.GetCRL(ctx, services.GetCRLResponseInput{ID: root.ID})
		if err != nil {
			return err
		}
		for _, serial := range revokedSerials(crl) {
			if serial == sub.Certificate.SerialNumber {
				return nil
			}
		}
		return errs.ErrCRLNotFound
	}))
	waitForStatus(t, sub.ID, models.CRLSettingsFinal)
}

// Settings of a CA already revoked, as the migration leaves them or after a lost event, get their final CRL from the
// reconciliation the monitor runs.
func TestReconciliationFinalizesTheSettingsOfARevokedCA(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	ca, err := initCAForVA(serverTest.CA.Service)
	require.NoError(t, err)
	waitForInitialCRL(t, ca.ID)
	_, err = serverTest.CA.Service.UpdateCAStatus(ctx, services.UpdateCAStatusInput{CAID: ca.ID, Status: models.StatusRevoked, RevocationReason: ocsp.KeyCompromise})
	require.NoError(t, err)
	final := waitForStatus(t, ca.ID, models.CRLSettingsFinal)
	// Back to ACTIVE, as if the VA had never seen the revocation.
	require.NoError(t, vaSchemaDB(t).Exec(`UPDATE crl_settings s SET status = 'ACTIVE', signer_engine_id = c.engine_id,
		signer_key_id = c.key_id FROM ca.certificates c WHERE c.serial_number = s.signer_serial_number AND s.ca_id = ?`, ca.ID).Error)

	got, err := serverTest.VA.CRLService.ReconcileCRLSettings(ctx, services.ReconcileCRLSettingsInput{CAID: ca.ID})
	require.NoError(t, err)
	require.Equal(t, models.CRLSettingsFinal, got.Status)
	require.Equal(t, 1, got.LatestCRL.Version.Cmp(final.LatestCRL.Version.Int), "a new final CRL is issued")
	crl, err := serverTest.VA.HttpVASDK.GetCRL(ctx, services.GetCRLResponseInput{ID: ca.ID})
	require.NoError(t, err)
	require.True(t, crl.NextUpdate.Equal(ca.Certificate.ValidTo.Truncate(time.Second)))
}

// Deleting one of two CAs on the same key keeps the key: the other one still uses it, and still gets CRLs.
func TestDeletingOneOfTwoCAsOnTheSameKeyKeepsTheKey(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSvc := serverTest.CA.Service
	owner, err := initCAForVA(caSvc)
	require.NoError(t, err)
	waitForInitialCRL(t, owner.ID)
	shared, err := caSvc.CreateCA(ctx, services.CreateCAInput{
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048, KeyID: "pkcs11:token-id=" + owner.Certificate.EngineID + ";id=" + owner.Certificate.KeyID + ";type=private"},
		Subject:      models.Subject{CommonName: "Shared key CA"},
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(24 * time.Hour)},
		ProfileID:    owner.ProfileID,
	})
	require.NoError(t, err)
	before := waitForInitialCRL(t, shared.ID)

	_, err = caSvc.UpdateCAStatus(ctx, services.UpdateCAStatusInput{CAID: owner.ID, Status: models.StatusRevoked, RevocationReason: ocsp.KeyCompromise})
	require.NoError(t, err)
	waitForStatus(t, owner.ID, models.CRLSettingsFinal)
	require.NoError(t, caSvc.DeleteCA(ctx, services.DeleteCAInput{CAID: owner.ID}))
	require.True(t, kmsKeyExists(t, shared.Certificate), "the other CA still uses the key")

	crl, err := serverTest.VA.CRLService.CalculateCRL(ctx, services.CalculateCRLInput{CAID: shared.ID})
	require.NoError(t, err)
	require.Equal(t, 1, crl.Number.Cmp(before.LatestCRL.Version.Int))
}

// The VA reaches the CA over HTTP: a deleted CA has to read as such, or the settings of a CA whose ca.delete event was
// lost would never be archived.
func TestReconciliationArchivesTheSettingsOfADeletedCA(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	ca, err := initCAForVA(serverTest.CA.Service)
	require.NoError(t, err)
	waitForInitialCRL(t, ca.ID)
	_, err = serverTest.CA.Service.UpdateCAStatus(ctx, services.UpdateCAStatusInput{CAID: ca.ID, Status: models.StatusRevoked, RevocationReason: ocsp.KeyCompromise})
	require.NoError(t, err)
	waitForStatus(t, ca.ID, models.CRLSettingsFinal)
	require.NoError(t, serverTest.CA.Service.DeleteCA(ctx, services.DeleteCAInput{CAID: ca.ID}))
	waitForStatus(t, ca.ID, models.CRLSettingsArchived)
	// Back to FINAL, as if the VA had never seen the deletion.
	require.NoError(t, vaSchemaDB(t).Exec(`UPDATE crl_settings SET status = 'FINAL', signer_serial_number = ? WHERE ca_id = ?`, ca.Certificate.SerialNumber, ca.ID).Error)

	got, err := serverTest.VA.CRLService.ReconcileCRLSettings(ctx, services.ReconcileCRLSettingsInput{CAID: ca.ID})
	require.NoError(t, err)
	require.Equal(t, models.CRLSettingsArchived, got.Status)
}
