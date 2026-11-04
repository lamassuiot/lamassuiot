package postgrestest

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	"github.com/stretchr/testify/require"
)

func TestVARoleSignerForeignKey(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgres.KMS_SCHEMA, postgres.CA_SCHEMA, postgres.VA_SCHEMA}, false)
	defer suite.AfterSuite()
	logger := helpers.SetupLogger(config.Info, "test", "VA FK")
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.CA_SCHEMA))
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.VA_SCHEMA))
	certs, err := postgres.NewCertificateRepository(logger, suite.DB[postgres.CA_SCHEMA])
	require.NoError(t, err)
	roles, err := postgres.NewVARepository(logger, suite.DB[postgres.VA_SCHEMA])
	require.NoError(t, err)
	ctx := context.Background()
	cert := newTestCertificate(t, 101, "", "")
	_, err = certs.Insert(ctx, cert)
	require.NoError(t, err)
	role := &models.VARole{CASubjectKeyID: "role", LatestCRL: models.LatestCRLMeta{Version: models.BigInt{Int: big.NewInt(0)}}, CRLOptions: models.VACRLRole{
		SignerCertificateSerialNumber: "missing", Validity: models.TimeDuration(time.Hour),
	}}
	_, err = roles.Insert(ctx, role)
	require.ErrorIs(t, err, errs.ErrCertificateNotFound)
	role.CRLOptions.SignerCertificateSerialNumber = cert.SerialNumber
	_, err = roles.Insert(ctx, role)
	require.NoError(t, err)
	role.CRLOptions.SignerCertificateSerialNumber = "missing"
	_, err = roles.Update(ctx, role)
	require.ErrorIs(t, err, errs.ErrCertificateNotFound)
	_, stored, err := roles.Get(ctx, "role")
	require.NoError(t, err)
	require.Equal(t, cert.SerialNumber, stored.CRLOptions.SignerCertificateSerialNumber)
	require.ErrorIs(t, certs.Delete(ctx, cert.SerialNumber), errs.ErrCertificateInUse)
	require.Error(t, suite.DB[postgres.VA_SCHEMA].Exec(`INSERT INTO va_role (ca_ski, crl_signer_certificate_serial_number) VALUES ('raw', 'absent')`).Error)
	require.Error(t, suite.DB[postgres.VA_SCHEMA].Exec(`INSERT INTO va_role (ca_ski) VALUES ('no-signer')`).Error)
	require.NoError(t, suite.DB[postgres.CA_SCHEMA].Exec(`UPDATE certificates SET serial_number = 'renamed' WHERE serial_number = ?`, cert.SerialNumber).Error)
	_, stored, err = roles.Get(ctx, "role")
	require.NoError(t, err)
	require.Equal(t, "renamed", stored.CRLOptions.SignerCertificateSerialNumber)
	require.NoError(t, suite.DB[postgres.VA_SCHEMA].Exec(`DELETE FROM va_role WHERE ca_ski = 'role'`).Error)
	require.NoError(t, certs.Delete(ctx, "renamed"))
}
