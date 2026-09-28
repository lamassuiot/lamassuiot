package postgrestest

import (
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	postgres "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"
	"github.com/stretchr/testify/require"
)

// A CA without issuance profile (empty profile_id) is valid, while a profile of
// another tenant is still rejected by the composite foreign key.
func TestCAProfileForeignKeyIsOptionalButTenantScoped(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgres.CA_DB_NAME}, false)
	defer suite.AfterSuite()
	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "CA profile FK test")
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.CA_DB_NAME))
	db := suite.DB[postgres.CA_DB_NAME]

	for _, serial := range []string{"serial-a1", "serial-a2", "serial-a3"} {
		require.NoError(t, db.Exec("INSERT INTO certificates (serial_number, tenant_id) VALUES (?, 'tenant-a')", serial).Error)
	}
	require.NoError(t, db.Exec("INSERT INTO issuance_profiles (id, tenant_id, name, validity_type) VALUES ('profile-a', 'tenant-a', 'a', 'Duration'), ('profile-b', 'tenant-b', 'b', 'Duration')").Error)

	require.NoError(t, db.Exec(
		"INSERT INTO ca_certificates (serial_number, id, tenant_id, profile_id) VALUES ('serial-a1', 'ca-no-profile', 'tenant-a', '')").Error,
		"a CA without profile must be accepted")
	require.NoError(t, db.Exec(
		"INSERT INTO ca_certificates (serial_number, id, tenant_id, profile_id) VALUES ('serial-a2', 'ca-own-profile', 'tenant-a', 'profile-a')").Error)
	require.Error(t, db.Exec(
		"INSERT INTO ca_certificates (serial_number, id, tenant_id, profile_id) VALUES ('serial-a3', 'ca-foreign-profile', 'tenant-a', 'profile-b')").Error,
		"a profile of another tenant must be rejected")
}
