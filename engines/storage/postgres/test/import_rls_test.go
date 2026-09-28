package postgrestest

import (
	"fmt"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	postgresstorage "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestTenantRLSRejectsImportIntoAnotherTenant(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgresstorage.CA_DB_NAME, postgresstorage.KMS_DB_NAME}, false)
	defer suite.AfterSuite()

	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Import RLS test")
	const appPassword = "import-rls-test"
	require.NoError(t, postgresstorage.MigrateDatabase(logger, cfg, postgresstorage.CA_DB_NAME))
	require.NoError(t, postgresstorage.MigrateDatabase(logger, cfg, postgresstorage.KMS_DB_NAME))

	caAdminDB := suite.DB[postgresstorage.CA_DB_NAME]
	kmsAdminDB := suite.DB[postgresstorage.KMS_DB_NAME]
	require.NoError(t, caAdminDB.Exec("ALTER ROLE lamassu_app PASSWORD 'import-rls-test'").Error)
	require.NoError(t, kmsAdminDB.Exec("ALTER ROLE lamassu_app PASSWORD 'import-rls-test'").Error)
	caAppDB := openTenantAppDB(t, cfg.Hostname, cfg.Port, postgresstorage.CA_DB_NAME, appPassword)
	kmsAppDB := openTenantAppDB(t, cfg.Hostname, cfg.Port, postgresstorage.KMS_DB_NAME, appPassword)

	err := postgresstorage.WithTenantTransaction(testTenantContext("tenant-a"), caAppDB, func(tx *gorm.DB) error {
		return tx.Exec("INSERT INTO certificates (serial_number, tenant_id) VALUES (?, ?)", "imported-cross-ca", "tenant-b").Error
	})
	require.Error(t, err)

	err = postgresstorage.WithTenantTransaction(testTenantContext("tenant-a"), caAppDB, func(tx *gorm.DB) error {
		return tx.Exec("INSERT INTO certificates (serial_number, tenant_id) VALUES (?, ?)", "imported-ca", "tenant-a").Error
	})
	require.NoError(t, err)

	err = postgresstorage.WithTenantTransaction(testTenantContext("tenant-a"), kmsAppDB, func(tx *gorm.DB) error {
		return tx.Exec("INSERT INTO kms_keys (key_id, name, algorithm, size, public_key, tenant_id) VALUES (?, ?, ?, ?, ?, ?)", "imported-cross-key", "Imported cross key", "RSA", 2048, "public-cross", "tenant-b").Error
	})
	require.Error(t, err)

	err = postgresstorage.WithTenantTransaction(testTenantContext("tenant-a"), kmsAppDB, func(tx *gorm.DB) error {
		return tx.Exec("INSERT INTO kms_keys (key_id, name, algorithm, size, public_key, tenant_id) VALUES (?, ?, ?, ?, ?, ?)", "imported-key", "Imported key", "RSA", 2048, "public-a", "tenant-a").Error
	})
	require.NoError(t, err)
}

func openTenantAppDB(t *testing.T, host string, port int, database string, password string) *gorm.DB {
	db, err := gorm.Open(postgres.Open(fmt.Sprintf(
		"host=%s port=%d user=lamassu_app dbname=%s password=%s sslmode=disable",
		host, port, database, password,
	)), &gorm.Config{})
	require.NoError(t, err)
	return db
}
