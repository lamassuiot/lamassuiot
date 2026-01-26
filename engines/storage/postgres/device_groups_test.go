package postgres

import (
	"context"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	postgrestest "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/test"
	"github.com/stretchr/testify/assert"
)

func TestDeviceGroupsRepository(t *testing.T) {
	logger := helpers.SetupLogger(config.Info, "test", "device-groups-repo")

	t.Run("CRUD Operations", func(t *testing.T) {
		// Setup
		pgConfig, suite := postgrestest.BeforeSuite([]string{"devicemanager"}, false)
		defer suite.AfterSuite()
		suite.BeforeEach()

		db := suite.DB["devicemanager"]

		// Run migrations
		migrator := NewMigrator(logger, db)
		migrator.MigrateToLatest()

		repo, err := NewDeviceGroupsRepository(logger, db)
		assert.NoError(t, err)

		ctx := context.Background()

		// Test Insert
		rootGroup := &models.DeviceGroup{
			ID:          "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
			Name:        "Root Group",
			Description: "Test root group",
			Criteria: []models.DeviceGroupFilterOption{
				{Field: "status", FilterOperation: 12, Value: "valid"},
			},
		}
		inserted, err := repo.Insert(ctx, rootGroup)
		assert.NoError(t, err)
		assert.NotNil(t, inserted)
		assert.Equal(t, "Root Group", inserted.Name)

		// Test SelectByID
		exists, found, err := repo.SelectByID(ctx, "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11")
		assert.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, "Root Group", found.Name)

		// Test Count
		count, err := repo.Count(ctx)
		assert.NoError(t, err)
		assert.Equal(t, 1, count)

		// Test Update
		found.Description = "Updated description"
		updated, err := repo.Update(ctx, found)
		assert.NoError(t, err)
		assert.Equal(t, "Updated description", updated.Description)

		// Test Delete
		err = repo.Delete(ctx, "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11")
		assert.NoError(t, err)

		exists, _, err = repo.SelectByID(ctx, "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11")
		assert.NoError(t, err)
		assert.False(t, exists)

		_ = pgConfig // Just to avoid unused warning
	})

	t.Run("SelectAncestors - Hierarchy Traversal", func(t *testing.T) {
		pgConfig, suite := postgrestest.BeforeSuite([]string{"devicemanager"}, false)
		defer suite.AfterSuite()
		suite.BeforeEach()

		db := suite.DB["devicemanager"]

		// Run migrations
		migrator := NewMigrator(logger, db)
		migrator.MigrateToLatest()

		repo, err := NewDeviceGroupsRepository(logger, db)
		assert.NoError(t, err)

		ctx := context.Background()

		// Create hierarchy: root -> child -> grandchild
		root := &models.DeviceGroup{
			ID:          "10000000-0000-0000-0000-000000000001",
			Name:        "Root",
			Description: "Root group",
			Criteria:    []models.DeviceGroupFilterOption{{Field: "status", FilterOperation: 12, Value: "valid"}},
		}
		_, err = repo.Insert(ctx, root)
		assert.NoError(t, err)

		parentID := "10000000-0000-0000-0000-000000000001"
		child := &models.DeviceGroup{
			ID:          "10000000-0000-0000-0000-000000000002",
			Name:        "Child",
			Description: "Child group",
			ParentID:    &parentID,
			Criteria:    []models.DeviceGroupFilterOption{{Field: "tags", FilterOperation: 7, Value: "region:eu"}},
		}
		_, err = repo.Insert(ctx, child)
		assert.NoError(t, err)

		childParentID := "10000000-0000-0000-0000-000000000002"
		grandchild := &models.DeviceGroup{
			ID:          "10000000-0000-0000-0000-000000000003",
			Name:        "Grandchild",
			Description: "Grandchild group",
			ParentID:    &childParentID,
			Criteria:    []models.DeviceGroupFilterOption{{Field: "metadata.temp", FilterOperation: 10, Value: "50"}},
		}
		_, err = repo.Insert(ctx, grandchild)
		assert.NoError(t, err)

		// Test SelectAncestors from grandchild
		ancestors, err := repo.SelectAncestors(ctx, "10000000-0000-0000-0000-000000000003")
		assert.NoError(t, err)
		assert.Len(t, ancestors, 3) // Should include grandchild, child, and root

		// Verify order (should be from child to root, or root to child depending on implementation)
		groupIDs := make([]string, len(ancestors))
		for i, g := range ancestors {
			groupIDs[i] = g.ID
		}
		// The order should include all three groups
		assert.Contains(t, groupIDs, "10000000-0000-0000-0000-000000000001") // root
		assert.Contains(t, groupIDs, "10000000-0000-0000-0000-000000000002") // child
		assert.Contains(t, groupIDs, "10000000-0000-0000-0000-000000000003") // grandchild

		_ = pgConfig // Just to avoid unused warning
	})

	t.Run("Circular Reference Prevention - Self Reference", func(t *testing.T) {
		pgConfig, suite := postgrestest.BeforeSuite([]string{"devicemanager"}, false)
		defer suite.AfterSuite()
		suite.BeforeEach()

		db := suite.DB["devicemanager"]

		// Run migrations
		migrator := NewMigrator(logger, db)
		migrator.MigrateToLatest()

		repo, err := NewDeviceGroupsRepository(logger, db)
		assert.NoError(t, err)

		ctx := context.Background()

		// Try to create a group with itself as parent
		selfParent := "20000000-0000-0000-0000-000000000001"
		group := &models.DeviceGroup{
			ID:          "20000000-0000-0000-0000-000000000001",
			Name:        "Self Reference",
			Description: "This should fail",
			ParentID:    &selfParent,
			Criteria:    []models.DeviceGroupFilterOption{},
		}

		_, err = repo.Insert(ctx, group)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "circular reference")

		_ = pgConfig // Just to avoid unused warning
	})

	t.Run("Circular Reference Prevention - Ancestor Chain", func(t *testing.T) {
		pgConfig, suite := postgrestest.BeforeSuite([]string{"devicemanager"}, false)
		defer suite.AfterSuite()
		suite.BeforeEach()

		db := suite.DB["devicemanager"]

		// Run migrations
		migrator := NewMigrator(logger, db)
		migrator.MigrateToLatest()

		repo, err := NewDeviceGroupsRepository(logger, db)
		assert.NoError(t, err)

		ctx := context.Background()

		// Create: A -> B -> C
		groupA := &models.DeviceGroup{
			ID:          "30000000-0000-0000-0000-000000000001",
			Name:        "Group A",
			Description: "Root",
			Criteria:    []models.DeviceGroupFilterOption{},
		}
		_, err = repo.Insert(ctx, groupA)
		assert.NoError(t, err)

		parentA := "30000000-0000-0000-0000-000000000001"
		groupB := &models.DeviceGroup{
			ID:          "30000000-0000-0000-0000-000000000002",
			Name:        "Group B",
			Description: "Child of A",
			ParentID:    &parentA,
			Criteria:    []models.DeviceGroupFilterOption{},
		}
		_, err = repo.Insert(ctx, groupB)
		assert.NoError(t, err)

		parentB := "30000000-0000-0000-0000-000000000002"
		groupC := &models.DeviceGroup{
			ID:          "30000000-0000-0000-0000-000000000003",
			Name:        "Group C",
			Description: "Child of B",
			ParentID:    &parentB,
			Criteria:    []models.DeviceGroupFilterOption{},
		}
		_, err = repo.Insert(ctx, groupC)
		assert.NoError(t, err)

		// Try to make A a child of C (creating A -> B -> C -> A)
		parentC := "30000000-0000-0000-0000-000000000003"
		groupA.ParentID = &parentC
		_, err = repo.Update(ctx, groupA)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "circular reference")

		_ = pgConfig // Just to avoid unused warning
	})
}
