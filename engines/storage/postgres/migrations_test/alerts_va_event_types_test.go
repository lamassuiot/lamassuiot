package migrationstest

import (
	"context"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	"github.com/stretchr/testify/require"
)

const alertsVAEventTypesMigrationVersion = 20261116120000

// Subscriptions match events by exact type, so the ones created for the VA role events must follow the rename of those
// events to the CRL settings ones, or they stop receiving them.
func TestAlertsSubscriptionsFollowTheRenamedVAEvents(t *testing.T) {
	logger := helpers.SetupLogger(config.Info, "test", "Alerts migration")
	cleanup, con := RunDB(t, logger, postgres.ALERTS_SCHEMA)
	defer cleanup()
	m := postgres.NewMigrator(logger, con).Goose
	ctx := context.Background()
	_, err := m.UpTo(ctx, alertsVAEventTypesMigrationVersion-1)
	require.NoError(t, err)

	require.NoError(t, con.Exec(`INSERT INTO subscriptions (id, user_id, event_type) VALUES
		('sub-update', 'user', 'va.role.update'),
		('sub-init', 'user', 'va.role.crl.init'),
		('sub-crl', 'user', 'va.role.crl.create'),
		('sub-ca', 'user', 'ca.create')`).Error)

	_, err = m.ApplyVersion(ctx, alertsVAEventTypesMigrationVersion, true)
	require.NoError(t, err)

	eventType := func(id string) string {
		var et string
		require.NoError(t, con.Raw(`SELECT event_type FROM subscriptions WHERE id = ?`, id).Scan(&et).Error)
		return et
	}
	require.Equal(t, string(models.EventUpdateCRLSettings), eventType("sub-update"))
	require.Equal(t, string(models.EventInitCRLSettings), eventType("sub-init"))
	require.Equal(t, string(models.EventCreateCRL), eventType("sub-crl"), "the CRL event keeps its published name")
	require.Equal(t, "ca.create", eventType("sub-ca"))
}
