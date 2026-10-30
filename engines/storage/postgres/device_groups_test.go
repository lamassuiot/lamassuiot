package postgres

import (
	"context"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	postgrestest "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func deviceGroupsTenantContext(tenantID string) context.Context {
	return core.WithTenantContext(context.Background(), core.TenantContext{
		OrganizationID: "organization",
		TenantID:       tenantID,
		ActorID:        "actor",
		ActorType:      "user",
		CorrelationID:  "correlation",
		Source:         "test",
		TenantStatus:   core.TenantActive,
		Validated:      true,
	})
}

func TestDeviceGroupsRepositoryTenantIsolation(t *testing.T) {
	logger := helpers.SetupLogger(config.Info, "test", "device-groups-repo-tenant-isolation")

	_, suite := postgrestest.BeforeSuite([]string{"devicemanager"}, false)
	defer suite.AfterSuite()
	suite.BeforeEach()

	db := suite.DB["devicemanager"]
	migrator := NewMigrator(logger, db)
	migrator.MigrateToLatest()

	repo, err := NewDeviceGroupsRepository(logger, db)
	require.NoError(t, err)

	tenantA := deviceGroupsTenantContext("00000000-0000-0000-0000-000000000002")
	tenantB := deviceGroupsTenantContext("00000000-0000-0000-0000-000000000003")

	groupA, err := repo.Insert(tenantA, &models.DeviceGroup{
		ID:       "40000000-0000-0000-0000-000000000002",
		TenantID: "attacker-supplied-tenant",
		Name:     "Tenant A Group",
		Criteria: []models.DeviceGroupFilterOption{},
	})
	require.NoError(t, err)
	require.Equal(t, "00000000-0000-0000-0000-000000000002", groupA.TenantID)

	_, err = repo.Insert(tenantB, &models.DeviceGroup{
		ID:       "40000000-0000-0000-0000-000000000003",
		Name:     "Tenant B Group",
		Criteria: []models.DeviceGroupFilterOption{},
	})
	require.NoError(t, err)
	_, err = repo.Insert(tenantA, &models.DeviceGroup{
		ID:       "40000000-0000-0000-0000-000000000004",
		Name:     "Tenant A Group 2",
		Criteria: []models.DeviceGroupFilterOption{},
	})
	require.NoError(t, err)
	_, err = repo.Insert(tenantB, &models.DeviceGroup{
		ID:       "40000000-0000-0000-0000-000000000005",
		Name:     "Tenant B Group 2",
		Criteria: []models.DeviceGroupFilterOption{},
	})
	require.NoError(t, err)

	exists, found, err := repo.SelectByID(tenantB, groupA.ID)
	require.NoError(t, err)
	require.False(t, exists)
	require.Nil(t, found)

	exists, found, err = repo.SelectByID(tenantA, groupA.ID)
	require.NoError(t, err)
	require.True(t, exists)
	require.Equal(t, "Tenant A Group", found.Name)

	ancestors, err := repo.SelectAncestors(tenantB, groupA.ID)
	require.NoError(t, err)
	require.Empty(t, ancestors)

	ancestors, err = repo.SelectAncestors(tenantA, groupA.ID)
	require.NoError(t, err)
	require.Len(t, ancestors, 1)

	parentFromA := groupA.ID
	_, err = repo.Insert(tenantB, &models.DeviceGroup{
		ID:       "40000000-0000-0000-0000-000000000006",
		Name:     "Tenant B Child",
		ParentID: &parentFromA,
		Criteria: []models.DeviceGroupFilterOption{},
	})
	require.Error(t, err)

	updated := *groupA
	updated.Description = "hijacked"
	_, err = repo.Update(tenantB, &updated)
	require.Error(t, err)

	err = repo.Delete(tenantB, groupA.ID)
	require.Error(t, err)

	exists, found, err = repo.SelectByID(tenantA, groupA.ID)
	require.NoError(t, err)
	require.True(t, exists)
	require.Equal(t, "Tenant A Group", found.Name)

	countA, err := repo.Count(tenantA)
	require.NoError(t, err)
	require.Equal(t, 2, countA)

	countB, err := repo.Count(tenantB)
	require.NoError(t, err)
	require.Equal(t, 2, countB)

	query := &resources.QueryParameters{
		PageSize: 1,
		Sort: resources.SortOptions{
			SortMode:  resources.SortModeAsc,
			SortField: "id",
		},
	}
	var tenantAPage []string
	bookmark, err := repo.SelectAll(tenantA, storage.StorageListRequest[models.DeviceGroup]{
		QueryParams: query,
		ApplyFunc:   func(group models.DeviceGroup) { tenantAPage = append(tenantAPage, group.Name) },
	})
	require.NoError(t, err)
	require.NotEmpty(t, bookmark)
	require.Equal(t, []string{"Tenant A Group"}, tenantAPage)

	tenantAPage = nil
	_, err = repo.SelectAll(tenantA, storage.StorageListRequest[models.DeviceGroup]{
		QueryParams: &resources.QueryParameters{NextBookmark: bookmark},
		ApplyFunc:   func(group models.DeviceGroup) { tenantAPage = append(tenantAPage, group.Name) },
	})
	require.NoError(t, err)
	require.Equal(t, []string{"Tenant A Group 2"}, tenantAPage)

	var tenantBPage []string
	_, err = repo.SelectAll(tenantB, storage.StorageListRequest[models.DeviceGroup]{
		QueryParams: &resources.QueryParameters{NextBookmark: bookmark},
		ApplyFunc:   func(group models.DeviceGroup) { tenantBPage = append(tenantBPage, group.Name) },
	})
	require.NoError(t, err)
	require.Equal(t, []string{"Tenant B Group 2"}, tenantBPage)
}
