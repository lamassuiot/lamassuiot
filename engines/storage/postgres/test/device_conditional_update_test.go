package postgrestest

import (
	"context"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// The status, identity slot and metadata writes only touch their own columns, and a decommissioned device is final:
// a writer that read the device before its decommission cannot bring it back.
func TestDeviceTargetedUpdates(t *testing.T) {
	_, suite := BeforeSuite([]string{"devicemanager"}, false)
	defer suite.AfterSuite()

	db := suite.DB["devicemanager"]
	logger := logrus.NewEntry(logrus.New())
	postgres.NewMigrator(logger, db).MigrateToLatest()
	repo, err := postgres.NewDeviceManagerRepository(logger, db)
	require.NoError(t, err)

	ctx := context.Background()
	insert := func(t *testing.T, id string) {
		t.Helper()
		suite.BeforeEach()
		_, err := repo.Insert(ctx, &models.Device{
			ID:                id,
			Status:            models.DeviceActive,
			CreationTimestamp: time.Now(),
			Tags:              []string{},
			Metadata:          map[string]any{"env": "prod"},
			IdentitySlot:      &models.Slot[string]{Status: models.SlotActive, Secrets: map[int]string{0: "sn-1"}},
			ExtraSlots:        map[string]*models.Slot[any]{},
		})
		require.NoError(t, err)
	}
	stored := func(t *testing.T, id string) *models.Device {
		t.Helper()
		exists, device, err := repo.SelectExists(ctx, id)
		require.NoError(t, err)
		require.True(t, exists)
		return device
	}
	revokedSlot := &models.Slot[string]{Status: models.SlotRevoke, Secrets: map[int]string{0: "sn-1"}}

	t.Run("StatusWritesOnlyStatusAndSlot", func(t *testing.T) {
		insert(t, "dev-status")
		device, err := repo.UpdateStatus(ctx, "dev-status", models.DeviceDecommissioned, revokedSlot)
		require.NoError(t, err)
		require.Equal(t, models.DeviceDecommissioned, device.Status)
		require.Equal(t, models.SlotRevoke, device.IdentitySlot.Status)
		require.Equal(t, map[string]any{"env": "prod"}, device.Metadata)
	})

	t.Run("StatusWithoutSlotKeepsTheSlot", func(t *testing.T) {
		insert(t, "dev-status-only")
		_, err := repo.UpdateStatus(ctx, "dev-status-only", models.DeviceRevoked, nil)
		require.NoError(t, err)
		device := stored(t, "dev-status-only")
		require.Equal(t, models.DeviceRevoked, device.Status)
		require.Equal(t, models.SlotActive, device.IdentitySlot.Status)
	})

	t.Run("DecommissionedDeviceRejectsStatusAndSlotWrites", func(t *testing.T) {
		insert(t, "dev-final")
		_, err := repo.UpdateStatus(ctx, "dev-final", models.DeviceDecommissioned, revokedSlot)
		require.NoError(t, err)

		_, err = repo.UpdateStatus(ctx, "dev-final", models.DeviceActive, nil)
		require.ErrorIs(t, err, errs.ErrDeviceInvalidStatus)
		_, err = repo.UpdateIdentitySlot(ctx, "dev-final", &models.Slot[string]{Status: models.SlotActive, ActiveVersion: 1, Secrets: map[int]string{1: "sn-2"}})
		require.ErrorIs(t, err, errs.ErrDeviceInvalidStatus)

		device := stored(t, "dev-final")
		require.Equal(t, models.DeviceDecommissioned, device.Status)
		require.Equal(t, models.SlotRevoke, device.IdentitySlot.Status)
		require.Equal(t, "sn-1", device.IdentitySlot.Secrets[0])
	})

	t.Run("SlotWritesOnlyTheSlot", func(t *testing.T) {
		insert(t, "dev-slot")
		_, err := repo.UpdateIdentitySlot(ctx, "dev-slot", &models.Slot[string]{Status: models.SlotRenewalWindow, Secrets: map[int]string{0: "sn-1"}})
		require.NoError(t, err)
		device := stored(t, "dev-slot")
		require.Equal(t, models.SlotRenewalWindow, device.IdentitySlot.Status)
		require.Equal(t, models.DeviceActive, device.Status)
	})

	// A metadata edit based on a read from before the decommission does not bring the device back.
	t.Run("MetadataDoesNotOverwriteTheStatus", func(t *testing.T) {
		insert(t, "dev-meta")
		_, err := repo.UpdateStatus(ctx, "dev-meta", models.DeviceDecommissioned, revokedSlot)
		require.NoError(t, err)

		device, err := repo.UpdateMetadata(ctx, "dev-meta", map[string]any{"env": "retired"})
		require.NoError(t, err)
		require.Equal(t, map[string]any{"env": "retired"}, device.Metadata)
		require.Equal(t, models.DeviceDecommissioned, stored(t, "dev-meta").Status)
	})

	t.Run("MissingDevice", func(t *testing.T) {
		suite.BeforeEach()
		_, err := repo.UpdateStatus(ctx, "missing", models.DeviceActive, nil)
		require.ErrorIs(t, err, errs.ErrDeviceNotFound)
		_, err = repo.UpdateIdentitySlot(ctx, "missing", revokedSlot)
		require.ErrorIs(t, err, errs.ErrDeviceNotFound)
		_, err = repo.UpdateMetadata(ctx, "missing", map[string]any{})
		require.ErrorIs(t, err, errs.ErrDeviceNotFound)
	})
}
