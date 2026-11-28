package oracle

import (
	"context"
	"regexp"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"gorm.io/gorm"
)

type deviceStore struct{ db *gorm.DB }
type deviceEventStore struct{ db *gorm.DB }

var _ storage.DeviceEventsRepo = (*deviceEventStore)(nil)
var devicePK = regexp.MustCompile(`(?i)\([^)]*\blamassu_device_pk\)`)
var deviceEventPK = regexp.MustCompile(`(?i)\([^)]*\blamassu_device_event_pk\)`)
var deviceFields = map[string]struct{}{"id": {}, "tags": {}, "status": {}, "icon": {}, "icon_color": {}, "creation_timestamp": {}, "metadata": {}, "dms_owner": {}, "identity_slot": {}, "extra_slots": {}}
var deviceSortFields = map[string]struct{}{"id": {}, "status": {}, "icon_color": {}, "creation_timestamp": {}, "dms_owner": {}, "metadata": {}}
var deviceEventFields = map[string]struct{}{"id": {}, "device_id": {}, "event_ts": {}, "event_type": {}, "description": {}, "source": {}, "structured_fields": {}}
var deviceEventSortFields = map[string]struct{}{"id": {}, "device_id": {}, "event_ts": {}, "event_type": {}, "source": {}}

func (s *deviceStore) Count(ctx context.Context, params *resources.QueryParameters) (int, error) {
	tx := s.db.WithContext(ctx).Table("devices")
	if params != nil {
		var err error
		tx, err = applyFilters(tx, params.Filters, deviceFields)
		if err != nil {
			return -1, err
		}
	}
	var count int64
	if err := tx.Count(&count).Error; err != nil {
		return -1, err
	}
	return int(count), nil
}

func (s *deviceStore) list(tx *gorm.DB, exhaustive bool, apply func(models.Device), params *resources.QueryParameters, opts map[string]any) (string, error) {
	req := storage.StorageListRequest[models.Device]{ExhaustiveRun: exhaustive, ApplyFunc: apply, QueryParams: params, ExtraOpts: opts}
	return listRows(tx, req, deviceFields, deviceSortFields, nil, nil, []string{"id"}, func(d models.Device) []any { return []any{d.ID} })
}
func (s *deviceStore) SelectAll(ctx context.Context, exhaustive bool, apply func(models.Device), params *resources.QueryParameters, opts map[string]any) (string, error) {
	return s.list(s.db.WithContext(ctx).Table("devices"), exhaustive, apply, params, opts)
}
func (s *deviceStore) SelectByDMS(ctx context.Context, id string, exhaustive bool, apply func(models.Device), params *resources.QueryParameters, opts map[string]any) (string, error) {
	return s.list(s.db.WithContext(ctx).Table("devices").Where("dms_owner = ?", id), exhaustive, apply, params, opts)
}
func (s *deviceStore) SelectExists(ctx context.Context, id string) (bool, *models.Device, error) {
	var device models.Device
	tx := s.db.WithContext(ctx).Table("devices").Where("id = ?", id).Limit(1).Find(&device)
	if tx.Error != nil {
		return false, nil, tx.Error
	}
	if tx.RowsAffected == 0 {
		return false, nil, nil
	}
	return true, &device, nil
}
func (s *deviceStore) Insert(ctx context.Context, device *models.Device) (*models.Device, error) {
	if err := s.db.WithContext(ctx).Table("devices").Create(device).Error; err != nil {
		if constraintError(err, "ORA-00001", devicePK) {
			return nil, gorm.ErrDuplicatedKey
		}
		return nil, err
	}
	return device, nil
}
func (s *deviceStore) Update(ctx context.Context, device *models.Device) (*models.Device, error) {
	tx := s.db.WithContext(ctx).Table("devices").Where("id = ?", device.ID).Select("*").Updates(device)
	if tx.Error != nil {
		return nil, tx.Error
	}
	if tx.RowsAffected != 1 {
		return nil, gorm.ErrRecordNotFound
	}
	return device, nil
}
func (s *deviceStore) Delete(ctx context.Context, id string) error {
	tx := s.db.WithContext(ctx).Table("devices").Where("id = ?", id).Delete(&models.Device{})
	if tx.Error != nil {
		return tx.Error
	}
	if tx.RowsAffected != 1 {
		return gorm.ErrRecordNotFound
	}
	return nil
}
func (s *deviceStore) DeviceEvents() storage.DeviceEventsRepo { return &deviceEventStore{db: s.db} }

func (s *deviceEventStore) Insert(ctx context.Context, event *models.DeviceEventRecord) (*models.DeviceEventRecord, error) {
	if err := s.db.WithContext(ctx).Table("device_events").Create(event).Error; err != nil {
		if constraintError(err, "ORA-00001", deviceEventPK) {
			return nil, gorm.ErrDuplicatedKey
		}
		return nil, err
	}
	return event, nil
}
func (s *deviceEventStore) SelectByDeviceID(ctx context.Context, req storage.StorageListRequest[models.DeviceEventRecord], deviceID string) (string, error) {
	return listRows(s.db.WithContext(ctx).Table("device_events").Where("device_id = ?", deviceID), req, deviceEventFields, deviceEventSortFields, nil, nil, []string{"id"}, func(event models.DeviceEventRecord) []any { return []any{event.ID} })
}
func (s *deviceEventStore) DeleteByDeviceID(ctx context.Context, deviceID string) error {
	return s.db.WithContext(ctx).Table("device_events").Where("device_id = ?", deviceID).Delete(&models.DeviceEventRecord{}).Error
}
