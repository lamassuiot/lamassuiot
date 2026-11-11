package va

import (
	"context"
	"crypto/x509"
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
)

func TestVARoleUsesItsReferencedSignerCertificate(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSvc := serverTest.CA.Service
	issuer, err := initCAForVA(caSvc)
	require.NoError(t, err)
	signer, err := caSvc.CreateCA(ctx, services.CreateCAInput{
		ID: "crl-signer", Subject: models.Subject{CommonName: "Configured CRL signer"},
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256},
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(24 * time.Hour)},
		ProfileID:    issuer.ProfileID,
	})
	require.NoError(t, err)
	var role *models.VARole
	require.NoError(t, tests.SleepRetry(5, 3*time.Second, func() error {
		var err error
		role, err = serverTest.VA.CRLService.GetVARole(ctx, services.GetVARoleInput{CASubjectKeyID: issuer.Certificate.SubjectKeyID})
		if err != nil {
			return err
		}
		// Wait for the initial CRL's write to finish before changing the role.
		if role.LatestCRL.Version.Int == nil || role.LatestCRL.Version.Int.Sign() == 0 {
			return errs.ErrVARoleNotFound
		}
		return nil
	}))
	require.Equal(t, issuer.Certificate.SerialNumber, role.CRLOptions.SignerCertificateSerialNumber)
	opts := role.CRLOptions
	opts.SignerCertificateSerialNumber = "missing-certificate"
	_, err = serverTest.VA.HttpVASDK.UpdateVARole(ctx, services.UpdateVARoleInput{CASubjectKeyID: role.CASubjectKeyID, CRLRole: opts})
	require.ErrorIs(t, err, errs.ErrCertificateNotFound)
	opts.SignerCertificateSerialNumber = signer.Certificate.SerialNumber
	_, err = serverTest.VA.HttpVASDK.UpdateVARole(ctx, services.UpdateVARoleInput{CASubjectKeyID: role.CASubjectKeyID, CRLRole: opts})
	require.ErrorIs(t, err, errs.ErrValidateBadRequest, "a direct CRL cannot use another issuer's certificate")
	reissued, err := caSvc.ReissueCA(ctx, services.ReissueCAInput{CAID: issuer.ID})
	require.NoError(t, err)
	require.NotEqual(t, issuer.Certificate.SerialNumber, reissued.Certificate.SerialNumber)
	opts.SignerCertificateSerialNumber = reissued.Certificate.SerialNumber
	updated, err := serverTest.VA.HttpVASDK.UpdateVARole(ctx, services.UpdateVARoleInput{CASubjectKeyID: role.CASubjectKeyID, CRLRole: opts})
	require.NoError(t, err)
	require.Equal(t, reissued.Certificate.SerialNumber, updated.CRLOptions.SignerCertificateSerialNumber)
	crl, err := serverTest.VA.CRLService.CalculateCRL(ctx, services.CalculateCRLInput{CASubjectKeyID: role.CASubjectKeyID})
	require.NoError(t, err)
	require.NoError(t, crl.CheckSignatureFrom((*x509.Certificate)(reissued.Certificate.Certificate)))
	require.NoError(t, crl.CheckSignatureFrom((*x509.Certificate)(issuer.Certificate.Certificate)))

	// FK existence alone cannot check cryptographic compatibility; generation must check it too.
	switch serverTest.Storage.Config.Provider {
	case cconfig.Oracle:
		cfg, err := cconfig.DecodeStruct[oracleconfig.Config](serverTest.Storage.Config.Config)
		require.NoError(t, err)
		db, err := oracle.OpenDatabase(ctx, cfg)
		require.NoError(t, err)
		defer db.Close()
		_, err = db.ExecContext(ctx, `UPDATE va_role SET crl_signer_certificate_serial_number = :1 WHERE ca_ski = :2`, signer.Certificate.SerialNumber, role.CASubjectKeyID)
		require.NoError(t, err)
	case cconfig.Postgres, "":
		cfg, err := cconfig.DecodeStruct[pconfig.PostgresPSEConfig](serverTest.Storage.Config.Config)
		require.NoError(t, err)
		db, err := postgres.CreatePostgresDBConnection(chelpers.SetupLogger(cconfig.Info, "Test", "VA signer"), cfg, postgres.VA_SCHEMA)
		require.NoError(t, err)
		pool, err := db.DB()
		require.NoError(t, err)
		defer pool.Close()
		require.NoError(t, db.Exec(`UPDATE va_role SET crl_signer_certificate_serial_number = ? WHERE ca_ski = ?`, signer.Certificate.SerialNumber, role.CASubjectKeyID).Error)
	default:
		t.Fatalf("unsupported storage provider for VA signer test: %s", serverTest.Storage.Config.Provider)
	}
	_, err = serverTest.VA.CRLService.CalculateCRL(ctx, services.CalculateCRLInput{CASubjectKeyID: role.CASubjectKeyID})
	require.ErrorIs(t, err, errs.ErrValidateBadRequest)
}
