package va

import (
	"context"
	"crypto/x509"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/assemblers/tests"
	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/oracle"
	oracleconfig "github.com/lamassuiot/lamassuiot/v4/engines/storage/oracle/config"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	pconfig "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/config"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestCRLSettingsUseTheirReferencedSignerCertificate(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSvc := serverTest.CA.Service
	issuer, err := initCAForVA(caSvc)
	require.NoError(t, err)
	signer, err := caSvc.CreateCA(ctx, services.CreateCAInput{
		Subject:      models.Subject{CommonName: "Configured CRL signer"},
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256},
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(24 * time.Hour)},
		ProfileID:    issuer.ProfileID,
	})
	require.NoError(t, err)
	role := waitForInitialCRL(t, issuer.ID)
	require.Equal(t, issuer.Certificate.SerialNumber, role.Options.SignerSerialNumber)
	opts := role.Options
	opts.SignerSerialNumber = "missing-certificate"
	_, err = serverTest.VA.HttpVASDK.UpdateCRLSettings(ctx, services.UpdateCRLSettingsInput{CAID: role.CAID, Options: opts})
	require.ErrorIs(t, err, errs.ErrCertificateNotFound)
	opts.SignerSerialNumber = signer.Certificate.SerialNumber
	_, err = serverTest.VA.HttpVASDK.UpdateCRLSettings(ctx, services.UpdateCRLSettingsInput{CAID: role.CAID, Options: opts})
	require.ErrorIs(t, err, errs.ErrValidateBadRequest, "a direct CRL cannot use another issuer's certificate")
	reissued, err := caSvc.ReissueCA(ctx, services.ReissueCAInput{CAID: issuer.ID})
	require.NoError(t, err)
	require.NotEqual(t, issuer.Certificate.SerialNumber, reissued.Certificate.SerialNumber)
	// The VA moves the signer to the reissued certificate asynchronously; wait for it so it cannot race the
	// signer changes below.
	waitForCRLSettings(t, role.CAID, func(r *models.CRLSettings) bool {
		return r.Options.SignerSerialNumber == reissued.Certificate.SerialNumber
	})
	opts.SignerSerialNumber = reissued.Certificate.SerialNumber
	updated, err := serverTest.VA.HttpVASDK.UpdateCRLSettings(ctx, services.UpdateCRLSettingsInput{CAID: role.CAID, Options: opts})
	require.NoError(t, err)
	require.Equal(t, reissued.Certificate.SerialNumber, updated.Options.SignerSerialNumber)
	crl, err := serverTest.VA.CRLService.CalculateCRL(ctx, services.CalculateCRLInput{CAID: role.CAID})
	require.NoError(t, err)
	require.NoError(t, crl.CheckSignatureFrom((*x509.Certificate)(reissued.Certificate.Certificate)))
	require.NoError(t, crl.CheckSignatureFrom((*x509.Certificate)(issuer.Certificate.Certificate)))

	// The database only checks that the signer and its key exist, not that they fit the CA: generation checks it.
	pointCRLSignerAt(t, role.CAID, signer.Certificate.SerialNumber)
	_, err = serverTest.VA.CRLService.CalculateCRL(ctx, services.CalculateCRLInput{CAID: role.CAID})
	require.ErrorIs(t, err, errs.ErrValidateBadRequest)
}

func TestCRLSettingsSignerFollowsCAReissue(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSvc := serverTest.CA.Service
	issuer, err := initCAForVA(caSvc)
	require.NoError(t, err)
	before := waitForInitialCRL(t, issuer.ID)
	require.Equal(t, issuer.Certificate.SerialNumber, before.Options.SignerSerialNumber)
	versionBefore := new(big.Int).Set(before.LatestCRL.Version.Int)

	reissued, err := caSvc.ReissueCA(ctx, services.ReissueCAInput{CAID: issuer.ID})
	require.NoError(t, err)

	after := waitForCRLSettings(t, issuer.ID, func(r *models.CRLSettings) bool {
		return r.Options.SignerSerialNumber == reissued.Certificate.SerialNumber &&
			r.LatestCRL.Version.Int.Cmp(versionBefore) > 0
	})

	// Only the signer changes; the rest of the CRL options are kept.
	expectedOptions := before.Options
	expectedOptions.SignerSerialNumber = reissued.Certificate.SerialNumber
	require.Equal(t, expectedOptions, after.Options)

	crl, err := serverTest.VA.HttpVASDK.GetCRL(ctx, services.GetCRLResponseInput{
		ID:             issuer.ID,
		Issuer:         (*x509.Certificate)(reissued.Certificate.Certificate),
		VerifyResponse: true,
	})
	require.NoError(t, err)
	require.Equal(t, 0, after.LatestCRL.Version.Int.Cmp(crl.Number), "the served CRL is the one regenerated after the reissue")
}

// waitForCRLSettings polls the CRL settings of a CA until ready accepts them, since the VA updates them from CA events.
func waitForCRLSettings(t *testing.T, caID string, ready func(*models.CRLSettings) bool) *models.CRLSettings {
	t.Helper()

	var settings *models.CRLSettings
	require.NoError(t, tests.SleepRetry(5, 3*time.Second, func() error {
		r, err := serverTest.VA.CRLService.GetCRLSettings(context.Background(), services.GetCRLSettingsInput{CAID: caID})
		if err != nil {
			return err
		}
		if !ready(r) {
			return fmt.Errorf("CRL settings of CA %s are not in the expected state yet", caID)
		}
		settings = r
		return nil
	}))

	return settings
}

// pointCRLSignerAt makes the CRL settings of a CA reference another signer certificate and its key directly in
// the database, to set states the VA never reaches on its own.
func pointCRLSignerAt(t *testing.T, caID, signerSerialNumber string) {
	t.Helper()
	update := `UPDATE crl_settings s SET signer_serial_number = c.serial_number, signer_engine_id = c.engine_id,
		signer_key_id = c.key_id FROM ca.certificates c WHERE c.serial_number = ? AND s.ca_id = ?`
	if onOracle() {
		// Oracle keeps every table in one schema and has no UPDATE ... FROM.
		update = `UPDATE crl_settings s SET (signer_serial_number, signer_engine_id, signer_key_id) =
			(SELECT c.serial_number, c.engine_id, c.key_id FROM certificates c WHERE c.serial_number = ?) WHERE s.ca_id = ?`
	}
	require.NoError(t, vaSchemaDB(t).Exec(update, signerSerialNumber, caID).Error)
}

// onOracle tells whether the tests run on the Oracle storage engine, whose SQL differs from PostgreSQL's.
func onOracle() bool { return serverTest.Storage.Config.Provider == cconfig.Oracle }

// vaSchemaDB opens the database that holds the CRL settings of the test storage engine, to set states the VA never
// reaches on its own. On Oracle every table is in that one schema.
func vaSchemaDB(t *testing.T) *gorm.DB {
	t.Helper()
	switch serverTest.Storage.Config.Provider {
	case cconfig.Oracle:
		cfg, err := cconfig.DecodeStruct[oracleconfig.Config](serverTest.Storage.Config.Config)
		require.NoError(t, err)
		pool, err := oracle.OpenDatabase(context.Background(), cfg)
		require.NoError(t, err)
		t.Cleanup(func() { _ = pool.Close() })
		db, err := oracle.OpenGORM(pool)
		require.NoError(t, err)
		return db
	case cconfig.Postgres, "":
		cfg, err := cconfig.DecodeStruct[pconfig.PostgresPSEConfig](serverTest.Storage.Config.Config)
		require.NoError(t, err)
		db, err := postgres.CreatePostgresDBConnection(chelpers.SetupLogger(cconfig.Info, "Test", "VA"), cfg, postgres.VA_SCHEMA)
		require.NoError(t, err)
		pool, err := db.DB()
		require.NoError(t, err)
		t.Cleanup(func() { _ = pool.Close() })
		return db
	default:
		t.Fatalf("unsupported storage provider for VA tests: %s", serverTest.Storage.Config.Provider)
		return nil
	}
}
