package migrationstest

import (
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/stretchr/testify/assert"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

var vaDBName = "va"

func migrationTest_VA_00000000000001_create_table(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	ApplyMigration(t, logger, con, vaDBName)

	tx := con.Exec(`INSERT INTO va_role
		(ca_ski, crl_refresh_interval, crl_validity, crl_subject_key_id_signer, crl_regenerate_on_revoke, latest_crl_version, latest_crl_valid_from, latest_crl_valid_until)
		VALUES('ca-ski-1', '24h', '48h', 'ca-ski-1', true, 3, '2024-11-25 10:46:28.914', '2024-11-27 10:46:28.914');
	`)
	if tx.Error != nil {
		t.Fatalf("failed to insert a va role: %v", tx.Error)
	}
}

func migrationTest_VA_20261028120000_backfill_default_tenant(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	ApplyMigration(t, logger, con, vaDBName)

	var total, backfilled int64
	tx := con.Raw("SELECT count(*) FROM va_role").Scan(&total)
	if tx.Error != nil {
		t.Fatalf("failed to count va_role rows: %v", tx.Error)
	}
	tx = con.Raw("SELECT count(*) FROM va_role WHERE tenant_id = ?", models.DefaultTenantID).Scan(&backfilled)
	if tx.Error != nil {
		t.Fatalf("failed to count backfilled va_role rows: %v", tx.Error)
	}

	assert.NotZero(t, total, "the test needs existing va_role rows before the backfill")
	assert.Equal(t, total, backfilled, "every existing va role must belong to the default tenant")
}

func migrationTest_VA_20261028130000_enforce_tenant_constraints(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	ApplyMigration(t, logger, con, vaDBName)

	tx := con.Exec(`INSERT INTO va_role (ca_ski) VALUES('ca-ski-without-tenant');`)
	assert.Error(t, tx.Error, "a va role without tenant_id must be rejected")

	tx = con.Exec(`INSERT INTO va_role (tenant_id, ca_ski) VALUES('tenant-b', 'ca-ski-1');`)
	if tx.Error != nil {
		t.Fatalf("the same ca_ski must be storable for another tenant: %v", tx.Error)
	}

	tx = con.Exec(`INSERT INTO va_role (tenant_id, ca_ski) VALUES('tenant-b', 'ca-ski-1');`)
	assert.Error(t, tx.Error, "a tenant cannot have two va roles for the same ca_ski")

	var pkCols string
	tx = con.Raw(`
		SELECT string_agg(a.attname, ',' ORDER BY k.ord)
		FROM pg_constraint con
		JOIN pg_class c ON c.oid = con.conrelid
		JOIN unnest(con.conkey) WITH ORDINALITY AS k(attnum, ord) ON true
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = k.attnum
		WHERE c.relname = 'va_role' AND con.contype = 'p'`).Scan(&pkCols)
	if tx.Error != nil {
		t.Fatalf("failed to read the va_role primary key: %v", tx.Error)
	}
	assert.Equal(t, "tenant_id,ca_ski", pkCols)
}

func TestVAMigrations(t *testing.T) {
	logger := helpers.SetupLogger(config.Info, "test", "test")
	cleanup, con := RunDB(t, logger, vaDBName)

	defer cleanup()

	migrationTest_VA_00000000000001_create_table(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v00000000000001_create_table")
	}

	migrationTest_VA_20261028120000_backfill_default_tenant(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v20261028120000_backfill_default_tenant")
	}

	migrationTest_VA_20261028130000_enforce_tenant_constraints(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v20261028130000_enforce_tenant_constraints")
	}
}
