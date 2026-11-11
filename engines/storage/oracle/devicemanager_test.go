package oracle

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	authzengine "github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/engine"
	authzmodels "github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/models"
	authzsdk "github.com/lamassuiot/lamassuiot/v4/connectors/authz/sdk"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"gorm.io/gorm"
)

func testDevices(t *testing.T, ctx context.Context, db *gorm.DB) {
	t.Helper()
	devices := &deviceStore{db: db}
	events := devices.DeviceEvents()
	now := time.Now().UTC().Truncate(time.Second)
	device := &models.Device{ID: "device-a", DMSOwner: "dms-a", Status: models.DeviceActive, CreationTimestamp: now,
		Tags: []string{"sensor", "quoted'tag"}, Metadata: map[string]any{"document": strings.Repeat("x", 12000)},
		IdentitySlot: &models.Slot[string]{Status: models.SlotActive, ActiveVersion: 1, SecretType: models.X509SlotProfileType, Secrets: map[int]string{1: "identity"}},
		ExtraSlots:   map[string]*models.Slot[any]{"token": {Status: models.SlotActive, SecretType: models.TokenSlotProfile, Secrets: map[int]any{1: "secret"}}},
	}
	if _, err := devices.Insert(ctx, device); err != nil {
		t.Fatal(err)
	}
	if _, err := devices.Insert(ctx, device); !errors.Is(err, gorm.ErrDuplicatedKey) {
		t.Fatalf("duplicate device: %v", err)
	}
	found, got, err := devices.SelectExists(ctx, device.ID)
	if err != nil || !found || !reflect.DeepEqual(got.Tags, device.Tags) || !reflect.DeepEqual(got.Metadata, device.Metadata) || !reflect.DeepEqual(got.IdentitySlot, device.IdentitySlot) || !reflect.DeepEqual(got.ExtraSlots, device.ExtraSlots) {
		t.Fatalf("device round trip: found=%v device=%+v error=%v", found, got, err)
	}
	second := *device
	second.ID = "device-b"
	if _, err := devices.Insert(ctx, &second); err != nil {
		t.Fatal(err)
	}
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path for Authz PKI schema")
	}
	pkiSchema := filepath.Join(filepath.Dir(sourceFile), "../../../connectors/authz/pki.json")
	policyEngine, err := authzengine.NewEngine(map[string]*gorm.DB{"pki": db}, map[string]string{"pki": pkiSchema})
	if err != nil {
		t.Fatalf("create Oracle-backed Authz engine: %v", err)
	}
	policies := authzengine.NewPolicyRegistry()
	if err := policies.AddPolicy(&authzmodels.Policy{ID: "oracle-device-policy", Name: "Oracle device policy", Rules: []*authzmodels.Rule{{
		Namespace: "pki", SchemaName: "devicemanager", EntityType: "device", Actions: []string{"read"}, DirectGrants: []string{device.ID},
	}}}); err != nil {
		t.Fatal(err)
	}
	authzAllowed, err := policyEngine.Authorize(ctx, policies, "pki", "devicemanager", "read", "device", map[string]string{"id": device.ID})
	if err != nil || !authzAllowed {
		t.Fatalf("Oracle Authz grant for device %s: allowed=%v error=%v", device.ID, authzAllowed, err)
	}
	authzAllowed, err = policyEngine.Authorize(ctx, policies, "pki", "devicemanager", "read", "device", map[string]string{"id": second.ID})
	if err != nil || authzAllowed {
		t.Fatalf("Oracle Authz denial for device %s: allowed=%v error=%v", second.ID, authzAllowed, err)
	}
	allowed := context.WithValue(ctx, authzsdk.AuthzQueryKey, `SELECT * FROM devicemanager.devices WHERE devicemanager.devices.id IN ('device-a')`)
	if count, err := devices.Count(allowed, nil); err != nil || count != 1 {
		t.Fatalf("authorized device count=%d error=%v", count, err)
	}
	var permitted []string
	if _, err := devices.SelectAll(allowed, false, func(d models.Device) { permitted = append(permitted, d.ID) }, &resources.QueryParameters{PageSize: 10}, nil); err != nil || !reflect.DeepEqual(permitted, []string{"device-a"}) {
		t.Fatalf("authorized devices=%v error=%v", permitted, err)
	}
	denied := context.WithValue(ctx, authzsdk.AuthzQueryKey, `SELECT * FROM devicemanager.devices WHERE devicemanager.devices.id IN ('device-a'' OR 1=1 --')`)
	if count, err := devices.Count(denied, nil); err != nil || count != 0 {
		t.Fatalf("quoted authorization value count=%d error=%v", count, err)
	}
	params := &resources.QueryParameters{PageSize: 1, Filters: []resources.FilterOption{{Field: "tags", FilterOperation: resources.StringArrayContains, Value: "quoted'tag"}}}
	if count, err := devices.Count(ctx, params); err != nil || count != 2 {
		t.Fatalf("device count=%d error=%v", count, err)
	}
	var ids []string
	bookmark, err := devices.SelectByDMS(ctx, "dms-a", false, func(d models.Device) { ids = append(ids, d.ID) }, params, nil)
	if err != nil || bookmark == "" {
		t.Fatalf("device first page: bookmark=%q error=%v", bookmark, err)
	}
	params.NextBookmark = bookmark
	bookmark, err = devices.SelectByDMS(ctx, "dms-a", false, func(d models.Device) { ids = append(ids, d.ID) }, params, nil)
	if err != nil || bookmark != "" || !reflect.DeepEqual(ids, []string{"device-a", "device-b"}) {
		t.Fatalf("device pages=%v bookmark=%q error=%v", ids, bookmark, err)
	}
	event := &models.DeviceEventRecord{ID: "event-a", DeviceID: device.ID, EventTS: now, EventType: "CREATED", Description: "created", Source: "service/devmanager", StructuredFields: map[string]any{"event": "created"}}
	if _, err := events.Insert(ctx, event); err != nil {
		t.Fatal(err)
	}
	if _, err := events.Insert(ctx, event); !errors.Is(err, gorm.ErrDuplicatedKey) {
		t.Fatalf("duplicate device event: %v", err)
	}
	missing := *event
	missing.ID, missing.DeviceID = "missing", "unknown"
	if _, err := events.Insert(ctx, &missing); err == nil {
		t.Fatal("event with missing device accepted")
	}
	var records []models.DeviceEventRecord
	if _, err := events.SelectByDeviceID(ctx, storage.StorageListRequest[models.DeviceEventRecord]{ApplyFunc: func(e models.DeviceEventRecord) { records = append(records, e) }}, device.ID); err != nil || len(records) != 1 || records[0].ID != event.ID || !reflect.DeepEqual(records[0].StructuredFields, event.StructuredFields) {
		t.Fatalf("device events=%+v error=%v", records, err)
	}
	if err := devices.Delete(ctx, device.ID); err != nil {
		t.Fatal(err)
	}
	var count int64
	if err := db.WithContext(ctx).Table("device_events").Where("device_id = ?", device.ID).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("device event cascade: count=%d error=%v", count, err)
	}
	if err := events.DeleteByDeviceID(ctx, second.ID); err != nil {
		t.Fatal(err)
	}
	if err := devices.Delete(ctx, second.ID); err != nil {
		t.Fatal(err)
	}
}
