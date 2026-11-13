package migrationstest

import (
	"context"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

const crlSettingsMigrationVersion = 20261111120000

type crlSettingsRow struct {
	CAID               string  `gorm:"column:ca_id"`
	LegacySKI          *string `gorm:"column:legacy_ski"`
	SignerSerialNumber *string `gorm:"column:signer_serial_number"`
	Validity           string  `gorm:"column:validity"`
	RefreshInterval    string  `gorm:"column:refresh_interval"`
	RegenerateOnRevoke bool    `gorm:"column:regenerate_on_revoke"`
	Status             string  `gorm:"column:status"`
	LatestCRLVersion   string  `gorm:"column:latest_crl_version"`
}

// prepareVAMigration leaves the va schema right before the crl_settings migration, with a simulated ca schema.
// roles maps each VA role (SKI) to its signer certificate, which must already be in caCertificates.
func prepareVAMigration(t *testing.T, caCertificates, caAuthorities string, roles ...string) (*goose.Provider, *gorm.DB, func() error) {
	t.Helper()
	logger := helpers.SetupLogger(config.Info, "test", "VA migration")
	cleanup, con := RunDB(t, logger, postgres.VA_SCHEMA)
	m := postgres.NewMigrator(logger, con).Goose
	ctx := context.Background()
	_, err := m.UpTo(ctx, 1)
	require.NoError(t, err)
	require.NoError(t, con.Exec(`CREATE SCHEMA ca;
		CREATE TABLE ca.certificates (serial_number text PRIMARY KEY, subject_key_id text, key_id text, issuer_meta_id text);
		CREATE TABLE ca.ca_certificates (id text, serial_number text PRIMARY KEY, creation_ts timestamptz)`).Error)
	if caCertificates != "" {
		require.NoError(t, con.Exec(`INSERT INTO ca.certificates VALUES `+caCertificates).Error)
	}
	if caAuthorities != "" {
		require.NoError(t, con.Exec(`INSERT INTO ca.ca_certificates VALUES `+caAuthorities).Error)
	}
	for _, ski := range roles {
		require.NoError(t, con.Exec(`INSERT INTO va_role (ca_ski, crl_subject_key_id_signer, crl_validity, crl_refresh_interval, crl_regenerate_on_revoke, latest_crl_version, latest_crl_valid_from, latest_crl_valid_until)
			VALUES (?, ?, '168h0m0s', '166h0m0s', true, 7, now(), now())`, ski, ski).Error)
	}
	_, err = m.ApplyVersion(ctx, 20261104121000, true)
	require.NoError(t, err)
	return m, con, cleanup
}

func TestCRLSettingsMigration(t *testing.T) {
	// c-b is the certificate of subordinate CA id-b (issued by id-a); c-orph and c-suborph belong to CAs already
	// deleted (#841): the CA row is gone, and for the subordinate the issuer metadata is the id of the parent.
	m, con, cleanup := prepareVAMigration(t,
		`('c-a','ski-a','key-a',NULL), ('c-b','ski-b','key-b','id-a'), ('c-orph','ski-orph','key-o',NULL), ('c-suborph','ski-so',NULL,'id-a')`,
		`('id-a','c-a','2020-01-01'), ('id-b','c-b','2021-01-01')`,
		"ski-a", "ski-b", "ski-orph", "ski-so")
	defer cleanup()
	logger := helpers.SetupLogger(config.Info, "test", "VA migration")

	_, err := m.ApplyVersion(context.Background(), crlSettingsMigrationVersion, true)
	require.NoError(t, err)

	get := func(caID string) crlSettingsRow {
		var row crlSettingsRow
		require.NoError(t, con.Raw(`SELECT * FROM crl_settings WHERE ca_id = ?`, caID).Scan(&row).Error)
		require.Equal(t, caID, row.CAID, "row for %s", caID)
		return row
	}

	t.Run("one row per role, keyed by the id of its CA", func(t *testing.T) {
		a := get("id-a")
		require.Equal(t, "ACTIVE", a.Status)
		require.NotNil(t, a.LegacySKI)
		require.Equal(t, "ski-a", *a.LegacySKI)
		require.NotNil(t, a.SignerSerialNumber)
		require.Equal(t, "c-a", *a.SignerSerialNumber)
		require.Equal(t, "168h0m0s", a.Validity)
		require.Equal(t, "166h0m0s", a.RefreshInterval)
		require.True(t, a.RegenerateOnRevoke)
		require.Equal(t, "7", a.LatestCRLVersion, "CRL numbering continues")
		require.Equal(t, "ACTIVE", get("id-b").Status)
	})

	t.Run("roles without CA are archived under a synthetic id", func(t *testing.T) {
		for _, ski := range []string{"ski-orph", "ski-so"} {
			o := get("legacy-" + ski)
			require.Equal(t, "ARCHIVED", o.Status)
			require.NotNil(t, o.LegacySKI)
			require.Equal(t, ski, *o.LegacySKI)
			require.Nil(t, o.SignerSerialNumber)
			require.Equal(t, "7", o.LatestCRLVersion, "the last published CRL stays reachable")
		}
		var parentRows int64
		require.NoError(t, con.Raw(`SELECT count(*) FROM crl_settings WHERE legacy_ski = 'ski-so' AND ca_id = 'id-a'`).Scan(&parentRows).Error)
		require.Zero(t, parentRows, "the issuer id of a subordinate is the id of its parent, not its own")
	})

	t.Run("legacy_ski is unique and the old table is gone", func(t *testing.T) {
		require.Error(t, con.Exec(`INSERT INTO crl_settings (ca_id, legacy_ski, status) VALUES ('other', 'ski-a', 'ACTIVE')`).Error)
		require.Error(t, con.Exec(`INSERT INTO crl_settings (ca_id, status) VALUES ('bad-status', 'PENDING')`).Error)
		var table *string
		require.NoError(t, con.Raw(`SELECT to_regclass('va_role')::text`).Scan(&table).Error)
		require.Nil(t, table)
	})

	t.Run("the signer certificate is protected while it is referenced", func(t *testing.T) {
		require.Error(t, con.Exec(`DELETE FROM ca.certificates WHERE serial_number = 'c-a'`).Error)
		require.NoError(t, con.Exec(`DELETE FROM ca.certificates WHERE serial_number = 'c-orph'`).Error, "archived rows keep no signer")
		require.Error(t, con.Exec(`UPDATE crl_settings SET signer_serial_number = 'missing' WHERE ca_id = 'id-a'`).Error)
		require.NoError(t, con.Exec(`UPDATE ca.certificates SET serial_number = 'c-a2' WHERE serial_number = 'c-a'`).Error)
		var serial string
		require.NoError(t, con.Raw(`SELECT signer_serial_number FROM crl_settings WHERE ca_id = 'id-a'`).Scan(&serial).Error)
		require.Equal(t, "c-a2", serial)
	})

	t.Run("rollback does nothing: the migration is irreversible", func(t *testing.T) {
		RollbackMigration(t, logger, con, postgres.VA_SCHEMA, "20261111120000_crl_settings")
		var vaRole, crlSettings *string
		require.NoError(t, con.Raw(`SELECT to_regclass('va_role')::text`).Scan(&vaRole).Error)
		require.Nil(t, vaRole, "va_role is not recreated")
		require.NoError(t, con.Raw(`SELECT to_regclass('crl_settings')::text`).Scan(&crlSettings).Error)
		require.NotNil(t, crlSettings, "crl_settings is kept")
	})
}

func TestCRLSettingsMigrationRefusesAmbiguousInstallations(t *testing.T) {
	for _, tc := range []struct {
		name, certificates, authorities, wantErr string
		roles                                    []string
	}{
		{
			name:         "a role matching more than one CA",
			certificates: `('c-1','ski','k',NULL), ('c-2','ski','k',NULL)`,
			authorities:  `('ca-1','c-1','2020-01-01'), ('ca-2','c-2','2021-01-01')`,
			roles:        []string{"ski"},
			wantErr:      "ca-1, ca-2",
		},
		{
			name:         "a signer certificate without key",
			certificates: `('c-nokey','ski',NULL,NULL)`,
			authorities:  `('ca-1','c-nokey','2020-01-01')`,
			roles:        []string{"ski"},
			wantErr:      "c-nokey",
		},
		{
			name:         "a CA id that cannot be a URL segment",
			certificates: `('c-1','ski','k',NULL)`,
			authorities:  `('team/root','c-1','2020-01-01')`,
			roles:        []string{"ski"},
			wantErr:      "team/root",
		},
		{
			name:         "a CA id equal to the SKI of another role",
			certificates: `('c-1','ski','k',NULL), ('c-2','other','k2',NULL)`,
			authorities:  `('other','c-1','2020-01-01'), ('ca-2','c-2','2021-01-01')`,
			roles:        []string{"ski", "other"},
			wantErr:      "other",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, con, cleanup := prepareVAMigration(t, tc.certificates, tc.authorities, tc.roles...)
			defer cleanup()

			_, err := m.ApplyVersion(context.Background(), crlSettingsMigrationVersion, true)
			require.ErrorContains(t, err, tc.wantErr)

			var roles int64
			require.NoError(t, con.Raw(`SELECT count(*) FROM va_role`).Scan(&roles).Error)
			require.EqualValues(t, len(tc.roles), roles, "nothing is migrated when the installation is refused")
		})
	}
}

func TestCRLSettingsMigrationRefusesLegacyIDClash(t *testing.T) {
	// ski-orph has no CA anymore, so its settings would be archived as legacy-ski-orph: an id a live CA already has.
	m, con, cleanup := prepareVAMigration(t,
		`('c-x','ski-x','key-x',NULL), ('c-orph','ski-orph','key-o',NULL)`,
		`('legacy-ski-orph','c-x','2020-01-01')`,
		"ski-orph")
	defer cleanup()

	_, err := m.ApplyVersion(context.Background(), crlSettingsMigrationVersion, true)
	require.ErrorContains(t, err, "VA role ski-orph: CA legacy-ski-orph has the id reserved for the archived settings of this role, whose CA was deleted. Recreate that CA with a different id before upgrading")

	var table *string
	require.NoError(t, con.Raw(`SELECT to_regclass('va_role')::text`).Scan(&table).Error)
	require.NotNil(t, table, "nothing is migrated when the installation is refused")
}
