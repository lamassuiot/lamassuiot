package postgres

import (
	"context"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type PostgresDeviceManagerStore struct {
	db               *gorm.DB
	querier          *DBQuerier[models.Device]
	deviceGroupsRepo storage.DeviceGroupsRepo
	deviceEventsRepo storage.DeviceEventsRepo
}

func NewDeviceManagerRepository(logger *logrus.Entry, db *gorm.DB) (storage.DeviceManagerRepo, error) {
	querier, err := TableQuery(logger, db, "devices", "id", models.Device{})
	if err != nil {
		return nil, err
	}

	// Create device groups repository
	deviceGroupsRepo, err := NewDeviceGroupsRepository(logger, db)
	if err != nil {
		return nil, err
	}

	deviceEventsRepo, err := NewDeviceEventsRepository(logger, db)
	if err != nil {
		return nil, err
	}

	return &PostgresDeviceManagerStore{
		db:               db,
		querier:          querier,
		deviceGroupsRepo: deviceGroupsRepo,
		deviceEventsRepo: deviceEventsRepo,
	}, nil
}

func (db *PostgresDeviceManagerStore) Count(ctx context.Context, queryParams *resources.QueryParameters) (int, error) {
	filters := []resources.FilterOption{}
	if queryParams != nil {
		filters = queryParams.Filters
	}
	return db.querier.CountFiltered(ctx, filters, []GormExtraOps{})
}

func (db *PostgresDeviceManagerStore) SelectAll(ctx context.Context, exhaustiveRun bool, applyFunc func(models.Device), queryParams *resources.QueryParameters, extraOpts map[string]any) (string, error) {
	return db.querier.SelectAll(ctx, queryParams, []GormExtraOps{}, exhaustiveRun, applyFunc)
}

func (db *PostgresDeviceManagerStore) SelectByDMS(ctx context.Context, dmsID string, exhaustiveRun bool, applyFunc func(models.Device), queryParams *resources.QueryParameters, extraOpts map[string]any) (string, error) {
	opts := []GormExtraOps{
		{Query: "dms_owner = ?", AdditionalWhere: []any{dmsID}},
	}
	return db.querier.SelectAll(ctx, queryParams, opts, exhaustiveRun, applyFunc)
}

func (db *PostgresDeviceManagerStore) SelectExists(ctx context.Context, ID string) (bool, *models.Device, error) {
	return db.querier.SelectExists(ctx, ID, nil)
}

func (db *PostgresDeviceManagerStore) Update(ctx context.Context, device *models.Device) (*models.Device, error) {
	return db.querier.Update(ctx, device, device.ID)
}

func (db *PostgresDeviceManagerStore) UpdateStatus(ctx context.Context, ID string, status models.DeviceStatus, slot *models.Slot[string]) (*models.Device, error) {
	columns := []string{"status"}
	if slot != nil {
		columns = append(columns, "identity_slot")
	}
	return db.updateUnlessDecommissioned(ctx, ID, columns, &models.Device{Status: status, IdentitySlot: slot})
}

func (db *PostgresDeviceManagerStore) UpdateIdentitySlot(ctx context.Context, ID string, slot *models.Slot[string]) (*models.Device, error) {
	return db.updateUnlessDecommissioned(ctx, ID, []string{"identity_slot"}, &models.Device{IdentitySlot: slot})
}

func (db *PostgresDeviceManagerStore) UpdateMetadata(ctx context.Context, ID string, metadata map[string]any) (*models.Device, error) {
	// Select and a struct, not Save: Save upserts the whole row when the update matches none.
	tx := db.db.WithContext(ctx).Model(&models.Device{}).Where("id = ?", ID).
		Select("metadata").Updates(&models.Device{Metadata: metadata})
	if tx.Error != nil {
		return nil, tx.Error
	}
	if tx.RowsAffected == 0 {
		return nil, errs.ErrDeviceNotFound
	}
	return db.selectStored(ctx, ID)
}

// updateUnlessDecommissioned writes the given columns of the device, taken from values, unless the stored device is
// decommissioned. The condition is checked by the database, so a writer that read the device before its decommission
// cannot overwrite it.
func (db *PostgresDeviceManagerStore) updateUnlessDecommissioned(ctx context.Context, ID string, columns []string, values *models.Device) (*models.Device, error) {
	// Select and a struct, not Save: Save upserts the whole row when the update matches none.
	tx := db.db.WithContext(ctx).Model(&models.Device{}).
		Where("id = ? AND status IS DISTINCT FROM ?", ID, models.DeviceDecommissioned).
		Select(columns).Updates(values)
	if tx.Error != nil {
		return nil, tx.Error
	}
	if tx.RowsAffected == 0 {
		exists, _, err := db.querier.SelectExists(ctx, ID, nil)
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, errs.ErrDeviceNotFound
		}
		return nil, errs.ErrDeviceInvalidStatus
	}
	return db.selectStored(ctx, ID)
}

func (db *PostgresDeviceManagerStore) selectStored(ctx context.Context, ID string) (*models.Device, error) {
	exists, device, err := db.querier.SelectExists(ctx, ID, nil)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errs.ErrDeviceNotFound
	}
	return device, nil
}

func (db *PostgresDeviceManagerStore) Insert(ctx context.Context, device *models.Device) (*models.Device, error) {
	return db.querier.Insert(ctx, device, device.ID)
}

func (db *PostgresDeviceManagerStore) Delete(ctx context.Context, ID string) error {
	return db.querier.Delete(ctx, ID)
}

func (db *PostgresDeviceManagerStore) DeviceGroups() storage.DeviceGroupsRepo {
	return db.deviceGroupsRepo
}

func (db *PostgresDeviceManagerStore) DeviceEvents() storage.DeviceEventsRepo {
	return db.deviceEventsRepo
}
