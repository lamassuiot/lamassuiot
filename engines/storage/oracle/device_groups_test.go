package oracle

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"gorm.io/gorm"
)

func testDeviceGroups(t *testing.T, ctx context.Context, db *gorm.DB) {
	t.Helper()
	groups := &deviceGroupStore{db: db}
	now := time.Now().UTC().Truncate(time.Second)
	root := &models.DeviceGroup{ID: "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11", Name: "root", Criteria: []models.DeviceGroupFilterOption{{Field: "status", FilterOperation: 1, Value: "ACTIVE"}}, CreatedAt: now, UpdatedAt: now}
	child := &models.DeviceGroup{ID: "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a12", Name: "child", ParentID: &root.ID, Criteria: []models.DeviceGroupFilterOption{}, CreatedAt: now.Add(time.Second), UpdatedAt: now}
	grandchild := &models.DeviceGroup{ID: "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a13", Name: "grandchild", ParentID: &child.ID, Criteria: []models.DeviceGroupFilterOption{}, CreatedAt: now.Add(2 * time.Second), UpdatedAt: now}
	for _, group := range []*models.DeviceGroup{root, child, grandchild} {
		if _, err := groups.Insert(ctx, group); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := groups.Insert(ctx, root); !errors.Is(err, gorm.ErrDuplicatedKey) {
		t.Fatalf("duplicate group: %v", err)
	}
	ancestors, err := groups.SelectAncestors(ctx, grandchild.ID)
	if err != nil || len(ancestors) != 3 || ancestors[0].ID != root.ID || ancestors[1].ID != child.ID || ancestors[2].ID != grandchild.ID || !reflect.DeepEqual(ancestors[0].Criteria, root.Criteria) {
		t.Fatalf("ancestors=%+v error=%v", ancestors, err)
	}
	invalid := *root
	invalid.ParentID = &grandchild.ID
	if _, err := groups.Update(ctx, &invalid); err == nil {
		t.Fatal("accepted a group cycle")
	}
	var ids []string
	if _, err := groups.SelectAll(ctx, storage.StorageListRequest[models.DeviceGroup]{QueryParams: &resources.QueryParameters{PageSize: 2}, ExhaustiveRun: true, ApplyFunc: func(g models.DeviceGroup) { ids = append(ids, g.ID) }}); err != nil || !reflect.DeepEqual(ids, []string{root.ID, child.ID, grandchild.ID}) {
		t.Fatalf("groups=%v error=%v", ids, err)
	}
	if err := groups.Delete(ctx, root.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := groups.Count(ctx); err != nil || n != 0 {
		t.Fatalf("group cascade count=%d error=%v", n, err)
	}
	a := &models.DeviceGroup{ID: "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a21", Name: "a", Criteria: []models.DeviceGroupFilterOption{}}
	b := &models.DeviceGroup{ID: "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a22", Name: "b", Criteria: []models.DeviceGroupFilterOption{}}
	if _, err := groups.Insert(ctx, a); err != nil {
		t.Fatal(err)
	}
	if _, err := groups.Insert(ctx, b); err != nil {
		t.Fatal(err)
	}
	a.ParentID, b.ParentID = &b.ID, &a.ID
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, group := range []*models.DeviceGroup{a, b} {
		wg.Add(1)
		go func(g *models.DeviceGroup) { defer wg.Done(); _, err := groups.Update(ctx, g); results <- err }(group)
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !strings.Contains(err.Error(), "circular reference") {
			t.Fatalf("unexpected concurrent update error: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent cycle: %d successful updates, expected one", successes)
	}
}
