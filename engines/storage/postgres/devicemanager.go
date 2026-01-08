package postgres

import (
	"context"
	"fmt"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type PostgresDeviceManagerStore struct {
	db      *gorm.DB
	querier *postgresDBQuerier[models.Device]
}

func NewDeviceManagerRepository(logger *logrus.Entry, db *gorm.DB) (storage.DeviceManagerRepo, error) {
	querier, err := TableQuery(logger, db, "devices", "id", models.Device{})
	if err != nil {
		return nil, err
	}

	return &PostgresDeviceManagerStore{
		db:      db,
		querier: querier,
	}, nil
}

func (db *PostgresDeviceManagerStore) Count(ctx context.Context, queryParams *resources.QueryParameters) (int, error) {
	extraOpts := []gormExtraOps{}
	if queryParams != nil {
		extraOpts = append(extraOpts, buildGormExtraOpsFromFilters(queryParams.Filters)...)
	}
	return db.querier.Count(ctx, extraOpts)
}

func (db *PostgresDeviceManagerStore) SelectAll(ctx context.Context, exhaustiveRun bool, applyFunc func(models.Device), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	return db.querier.SelectAll(ctx, queryParams, []gormExtraOps{}, exhaustiveRun, applyFunc)
}

func (db *PostgresDeviceManagerStore) SelectByDMS(ctx context.Context, dmsID string, exhaustiveRun bool, applyFunc func(models.Device), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	opts := []gormExtraOps{
		{query: "dms_owner = ?", additionalWhere: []any{dmsID}},
	}
	return db.querier.SelectAll(ctx, queryParams, opts, exhaustiveRun, applyFunc)
}

func (db *PostgresDeviceManagerStore) SelectExists(ctx context.Context, ID string) (bool, *models.Device, error) {
	return db.querier.SelectExists(ctx, ID, nil)
}

func (db *PostgresDeviceManagerStore) Update(ctx context.Context, device *models.Device) (*models.Device, error) {
	return db.querier.Update(ctx, device, device.ID)
}

func (db *PostgresDeviceManagerStore) Insert(ctx context.Context, device *models.Device) (*models.Device, error) {
	return db.querier.Insert(ctx, device, device.ID)
}

func (db *PostgresDeviceManagerStore) Delete(ctx context.Context, ID string) error {
	return db.querier.Delete(ctx, ID)
}

// buildGormExtraOpsFromFilters converts QueryParameters filters to gormExtraOps format
// This helper function reuses the existing FilterOperandToWhereClause logic but adapts it
// to work with the gormExtraOps structure used for Count operations
func buildGormExtraOpsFromFilters(filters []resources.FilterOption) []gormExtraOps {
	extraOps := []gormExtraOps{}

	for _, filter := range filters {
		// Build the WHERE clause using existing filter logic
		// We need to construct the same query that FilterOperandToWhereClause would create
		whereClause, args := buildWhereClauseFromFilter(filter)
		if whereClause != "" {
			extraOps = append(extraOps, gormExtraOps{
				query:           whereClause,
				additionalWhere: args,
			})
		}
	}

	return extraOps
}

// buildWhereClauseFromFilter constructs WHERE clause and arguments from a FilterOption
func buildWhereClauseFromFilter(filter resources.FilterOption) (string, []any) {
	field := filter.Field

	switch filter.FilterOperation {
	case resources.StringEqual:
		return fmt.Sprintf("%s = ?", field), []any{filter.Value}
	case resources.StringEqualIgnoreCase:
		return fmt.Sprintf("%s ILIKE ?", field), []any{filter.Value}
	case resources.StringNotEqual:
		return fmt.Sprintf("%s <> ?", field), []any{filter.Value}
	case resources.StringNotEqualIgnoreCase:
		return fmt.Sprintf("%s NOT ILIKE ?", field), []any{filter.Value}
	case resources.StringContains:
		return fmt.Sprintf("%s LIKE ?", field), []any{fmt.Sprintf("%%%s%%", filter.Value)}
	case resources.StringContainsIgnoreCase:
		return fmt.Sprintf("%s ILIKE ?", field), []any{fmt.Sprintf("%%%s%%", filter.Value)}
	case resources.StringArrayContains:
		return fmt.Sprintf("%s LIKE ?", field), []any{fmt.Sprintf("%%%s%%", filter.Value)}
	case resources.StringArrayContainsIgnoreCase:
		return fmt.Sprintf("%s ILIKE ?", field), []any{fmt.Sprintf("%%%s%%", filter.Value)}
	case resources.StringNotContains:
		return fmt.Sprintf("%s NOT LIKE ?", field), []any{fmt.Sprintf("%%%s%%", filter.Value)}
	case resources.StringNotContainsIgnoreCase:
		return fmt.Sprintf("%s NOT ILIKE ?", field), []any{fmt.Sprintf("%%%s%%", filter.Value)}
	case resources.DateEqual:
		return fmt.Sprintf("%s = ?", field), []any{filter.Value}
	case resources.DateBefore:
		return fmt.Sprintf("%s < ?", field), []any{filter.Value}
	case resources.DateAfter:
		return fmt.Sprintf("%s > ?", field), []any{filter.Value}
	case resources.NumberEqual:
		return fmt.Sprintf("%s = ?", field), []any{filter.Value}
	case resources.NumberNotEqual:
		return fmt.Sprintf("%s <> ?", field), []any{filter.Value}
	case resources.NumberLessThan:
		return fmt.Sprintf("%s < ?", field), []any{filter.Value}
	case resources.NumberLessOrEqualThan:
		return fmt.Sprintf("%s <= ?", field), []any{filter.Value}
	case resources.NumberGreaterThan:
		return fmt.Sprintf("%s > ?", field), []any{filter.Value}
	case resources.NumberGreaterOrEqualThan:
		return fmt.Sprintf("%s >= ?", field), []any{filter.Value}
	case resources.EnumEqual:
		return fmt.Sprintf("%s = ?", field), []any{filter.Value}
	case resources.EnumNotEqual:
		return fmt.Sprintf("%s <> ?", field), []any{filter.Value}
	default:
		return "", nil
	}
}
