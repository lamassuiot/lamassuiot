package migrationstest

import (
	"context"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	"github.com/stretchr/testify/require"
)

func TestVARoleSignerMigration(t *testing.T) {
	for _, tc := range []struct{ name, certificates, current, want, wantErr string }{
		{"current CA after reissue", "('old', 'ski'), ('current', 'ski')", "('current')", "current", ""},
		{"unique standalone certificate", "('standalone', 'ski')", "", "standalone", ""},
		{"missing signer", "('unrelated', 'other')", "", "", "cannot resolve signer certificate"},
		{"ambiguous historical certificates", "('old', 'ski'), ('new', 'ski')", "", "", "cannot resolve signer certificate"},
		{"ambiguous current CAs", "('first', 'ski'), ('second', 'ski')", "('first'), ('second')", "", "cannot resolve signer certificate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger := helpers.SetupLogger(config.Info, "test", "VA migration")
			cleanup, con := RunDB(t, logger, postgres.VA_SCHEMA)
			defer cleanup()
			m := postgres.NewMigrator(logger, con)
			_, err := m.Goose.UpTo(context.Background(), 1)
			require.NoError(t, err)
			require.NoError(t, con.Exec(`CREATE SCHEMA ca; CREATE TABLE ca.certificates (serial_number text PRIMARY KEY, subject_key_id text); CREATE TABLE ca.ca_certificates (serial_number text PRIMARY KEY)`).Error)
			require.NoError(t, con.Exec(`INSERT INTO ca.certificates VALUES `+tc.certificates).Error)
			if tc.current != "" {
				require.NoError(t, con.Exec(`INSERT INTO ca.ca_certificates VALUES `+tc.current).Error)
			}
			require.NoError(t, con.Exec(`INSERT INTO va_role (ca_ski, crl_subject_key_id_signer) VALUES ('role', 'ski')`).Error)
			_, err = m.Goose.ApplyVersion(context.Background(), 20261104121000, true)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				var oldSigner string
				require.NoError(t, con.Raw(`SELECT crl_subject_key_id_signer FROM va_role WHERE ca_ski = 'role'`).Scan(&oldSigner).Error)
				require.Equal(t, "ski", oldSigner)
				return
			}
			require.NoError(t, err)
			var serial string
			require.NoError(t, con.Raw(`SELECT crl_signer_certificate_serial_number FROM va_role WHERE ca_ski = 'role'`).Scan(&serial).Error)
			require.Equal(t, tc.want, serial)
			var valid bool
			require.NoError(t, con.Raw(`SELECT convalidated FROM pg_constraint WHERE conname = 'va_role_signer_certificate_fk'`).Scan(&valid).Error)
			require.True(t, valid)
			require.Error(t, con.Exec(`UPDATE va_role SET crl_signer_certificate_serial_number = 'missing' WHERE ca_ski = 'role'`).Error)
			require.Error(t, con.Exec(`DELETE FROM ca.certificates WHERE serial_number = ?`, tc.want).Error)
			require.NoError(t, con.Exec(`UPDATE ca.certificates SET serial_number = 'renamed' WHERE serial_number = ?`, tc.want).Error)
			require.NoError(t, con.Raw(`SELECT crl_signer_certificate_serial_number FROM va_role WHERE ca_ski = 'role'`).Scan(&serial).Error)
			require.Equal(t, "renamed", serial)
			RollbackMigration(t, logger, con, postgres.VA_SCHEMA, "20261104121000_va_role_signer_certificate")
			require.NoError(t, con.Raw(`SELECT crl_subject_key_id_signer FROM va_role WHERE ca_ski = 'role'`).Scan(&serial).Error)
			require.Equal(t, "ski", serial)
		})
	}
}
