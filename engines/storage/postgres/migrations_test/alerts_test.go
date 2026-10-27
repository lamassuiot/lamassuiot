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

var alertsDBName = "alerts"

func migrationTest_Alerts_00000000000001_create_table(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	ApplyMigration(t, logger, con, alertsDBName)

	tx := con.Exec(`INSERT INTO events
		(event_type, "event", last_seen, total_seen)
		VALUES('certificate.expired', '{}', '2024-11-25 10:46:28.914', 37);
	`)
	if tx.Error != nil {
		t.Fatalf("failed to insert an event: %v", tx.Error)
	}

	tx = con.Exec(`INSERT INTO subscriptions
		(id, user_id, event_type, subscription_date, conditions, channel)
		VALUES('sub-1', 'user-1', 'certificate.expired', '2024-11-25 10:46:28.914', '[]', '{}');
	`)
	if tx.Error != nil {
		t.Fatalf("failed to insert a subscription: %v", tx.Error)
	}
}

func migrationTest_Alerts_20261027120000_backfill_default_tenant(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	ApplyMigration(t, logger, con, alertsDBName)

	for _, table := range []string{"events", "subscriptions"} {
		var total, backfilled int64
		tx := con.Raw("SELECT count(*) FROM " + table).Scan(&total)
		if tx.Error != nil {
			t.Fatalf("failed to count %s rows: %v", table, tx.Error)
		}
		tx = con.Raw("SELECT count(*) FROM "+table+" WHERE tenant_id = ?", models.DefaultTenantID).Scan(&backfilled)
		if tx.Error != nil {
			t.Fatalf("failed to count backfilled %s rows: %v", table, tx.Error)
		}

		assert.NotZero(t, total, "the test needs existing %s rows before the backfill", table)
		assert.Equal(t, total, backfilled, "every existing row of %s must belong to the default tenant", table)
	}

	var totalSeen int64
	tx := con.Raw("SELECT total_seen FROM events WHERE event_type = 'certificate.expired'").Scan(&totalSeen)
	if tx.Error != nil {
		t.Fatalf("failed to read the event counter: %v", tx.Error)
	}
	assert.Equal(t, int64(37), totalSeen, "the backfill must keep the event counter")
}

func migrationTest_Alerts_20261027130000_enforce_tenant_constraints(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	ApplyMigration(t, logger, con, alertsDBName)

	tx := con.Exec(`INSERT INTO subscriptions
		(id, user_id, event_type, subscription_date, conditions, channel)
		VALUES('sub-without-tenant', 'user-1', 'certificate.expired', '2024-11-25 10:46:28.914', '[]', '{}');
	`)
	assert.Error(t, tx.Error, "a subscription without tenant_id must be rejected")

	tx = con.Exec(`INSERT INTO events
		(event_type, "event", last_seen, total_seen)
		VALUES('ca.created', '{}', '2024-11-25 10:46:28.914', 1);
	`)
	assert.Error(t, tx.Error, "an event without tenant_id must be rejected")

	tx = con.Exec(`INSERT INTO events
		(tenant_id, event_type, "event", last_seen, total_seen)
		VALUES('tenant-b', 'certificate.expired', '{}', '2024-11-25 10:46:28.914', 1);
	`)
	if tx.Error != nil {
		t.Fatalf("the same event type must be storable for another tenant: %v", tx.Error)
	}

	var pkCols string
	tx = con.Raw(`
		SELECT string_agg(a.attname, ',' ORDER BY k.ord)
		FROM pg_constraint con
		JOIN pg_class c ON c.oid = con.conrelid
		JOIN unnest(con.conkey) WITH ORDINALITY AS k(attnum, ord) ON true
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = k.attnum
		WHERE c.relname = 'events' AND con.contype = 'p'`).Scan(&pkCols)
	if tx.Error != nil {
		t.Fatalf("failed to read the events primary key: %v", tx.Error)
	}
	assert.Equal(t, "tenant_id,event_type", pkCols)
}

func TestAlertsMigrations(t *testing.T) {
	logger := helpers.SetupLogger(config.Info, "test", "test")
	cleanup, con := RunDB(t, logger, alertsDBName)

	defer cleanup()

	migrationTest_Alerts_00000000000001_create_table(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v00000000000001_create_table")
	}

	migrationTest_Alerts_20261027120000_backfill_default_tenant(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v20261027120000_backfill_default_tenant")
	}

	migrationTest_Alerts_20261027130000_enforce_tenant_constraints(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v20261027130000_enforce_tenant_constraints")
	}
}
