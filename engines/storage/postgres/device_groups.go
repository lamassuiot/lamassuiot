package postgres

import (
	"context"
	"fmt"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

const deviceGroupsDBName = "device_groups"

type PostgresDeviceGroupsStore struct {
	db      *gorm.DB
	logger  *logrus.Entry
	querier *postgresDBQuerier[models.DeviceGroup]
}

func NewDeviceGroupsRepository(logger *logrus.Entry, db *gorm.DB) (storage.DeviceGroupsRepo, error) {
	querier, err := TableQuery(logger, db, deviceGroupsDBName, "id", models.DeviceGroup{})
	if err != nil {
		return nil, err
	}

	return &PostgresDeviceGroupsStore{
		db:      db,
		logger:  logger,
		querier: querier,
	}, nil
}

func (db *PostgresDeviceGroupsStore) Count(ctx context.Context) (int, error) {
	return db.querier.Count(ctx, []gormExtraOps{})
}

func (db *PostgresDeviceGroupsStore) SelectAll(ctx context.Context, req storage.StorageListRequest[models.DeviceGroup]) (string, error) {
	return db.querier.SelectAll(ctx, req.QueryParams, []gormExtraOps{}, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresDeviceGroupsStore) SelectByID(ctx context.Context, id string) (bool, *models.DeviceGroup, error) {
	return db.querier.SelectExists(ctx, id, nil)
}

// SelectAncestors returns all ancestor groups (parent chain) for a given group ID
// using a recursive CTE to traverse the hierarchy from the given group up to the root
func (db *PostgresDeviceGroupsStore) SelectAncestors(ctx context.Context, id string) ([]*models.DeviceGroup, error) {
	var ancestors []*models.DeviceGroup

	// Recursive CTE query to get all ancestors
	query := `
		WITH RECURSIVE ancestor_chain AS (
			-- Base case: start with the given group
			SELECT id, name, description, parent_id, criteria, created_at, updated_at
			FROM device_groups
			WHERE id = ?
			
			UNION ALL
			
			-- Recursive case: get parent of current group
			SELECT dg.id, dg.name, dg.description, dg.parent_id, dg.criteria, dg.created_at, dg.updated_at
			FROM device_groups dg
			INNER JOIN ancestor_chain ac ON dg.id = ac.parent_id
		)
		SELECT id, name, description, parent_id, criteria, created_at, updated_at
		FROM ancestor_chain
		ORDER BY created_at ASC
	`

	result := db.db.WithContext(ctx).Raw(query, id).Scan(&ancestors)
	if result.Error != nil {
		return nil, result.Error
	}

	return ancestors, nil
}

// Insert creates a new device group with validation to prevent circular references
func (db *PostgresDeviceGroupsStore) Insert(ctx context.Context, group *models.DeviceGroup) (*models.DeviceGroup, error) {
	// Validate for circular references if parent is set
	if group.ParentID != nil {
		if err := db.validateNoCircularReference(ctx, group.ID, *group.ParentID); err != nil {
			return nil, err
		}
	}

	return db.querier.Insert(ctx, group, group.ID)
}

// Update modifies an existing device group with validation to prevent circular references
func (db *PostgresDeviceGroupsStore) Update(ctx context.Context, group *models.DeviceGroup) (*models.DeviceGroup, error) {
	// Validate for circular references if parent is set or changed
	if group.ParentID != nil {
		if err := db.validateNoCircularReference(ctx, group.ID, *group.ParentID); err != nil {
			return nil, err
		}
	}

	return db.querier.Update(ctx, group, group.ID)
}

func (db *PostgresDeviceGroupsStore) Delete(ctx context.Context, id string) error {
	return db.querier.Delete(ctx, id)
}

// validateNoCircularReference checks that setting parentID for groupID would not create a circular reference
// This prevents a group from being an ancestor of itself
func (db *PostgresDeviceGroupsStore) validateNoCircularReference(ctx context.Context, groupID string, parentID string) error {
	// If trying to set self as parent, that's clearly circular
	if groupID == parentID {
		return fmt.Errorf("circular reference detected: group cannot be its own parent")
	}

	// Check if the proposed parent is actually a descendant of this group
	// Use a recursive query to find all descendants of groupID
	var count int64
	query := `
		WITH RECURSIVE descendant_chain AS (
			-- Base case: start with the current group
			SELECT id, parent_id
			FROM device_groups
			WHERE id = ?
			
			UNION ALL
			
			-- Recursive case: get all children
			SELECT dg.id, dg.parent_id
			FROM device_groups dg
			INNER JOIN descendant_chain dc ON dg.parent_id = dc.id
		)
		SELECT COUNT(*) FROM descendant_chain WHERE id = ?
	`

	result := db.db.WithContext(ctx).Raw(query, groupID, parentID).Scan(&count)
	if result.Error != nil {
		return result.Error
	}

	if count > 0 {
		return fmt.Errorf("circular reference detected: parent group is a descendant of this group")
	}

	return nil
}
