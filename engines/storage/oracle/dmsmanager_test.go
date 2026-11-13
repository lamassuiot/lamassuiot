package oracle

import (
	"context"
	"crypto/x509"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"gorm.io/gorm"
)

func testDMS(t *testing.T, ctx context.Context, db *gorm.DB) {
	t.Helper()
	store := &dmsStore{db: db}
	now := time.Now().UTC().Truncate(time.Second)
	dms := &models.DMS{ID: "dms-a", Name: "gateway", CreationDate: now,
		Metadata: map[string]any{"document": strings.Repeat("0123456789", 3000)},
		Settings: models.DMSSettings{
			ServerKeyGen:           models.ServerKeyGenSettings{Enabled: true, Key: models.ServerKeyGenKey{Type: models.KeyType(x509.RSA), Bits: 2048}},
			EnrollmentSettings:     models.EnrollmentSettings{EnrollmentProtocol: models.EST, RegistrationMode: models.PreRegistration, DeviceProvisionProfile: models.DeviceProvisionProfile{Tags: []string{"one", "two"}}},
			ReEnrollmentSettings:   models.ReEnrollmentSettings{RevokeOnReEnrollment: true, ReEnrollmentDelta: models.TimeDuration(time.Hour)},
			CADistributionSettings: models.CADistributionSettings{ManagedCAs: []string{"ca-a", "ca-b"}},
			IssuanceProfileID:      "profile",
		},
	}
	if _, err := store.Insert(ctx, dms); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Insert(ctx, dms); !errors.Is(err, gorm.ErrDuplicatedKey) {
		t.Fatalf("duplicate DMS: %v", err)
	}
	found, got, err := store.SelectExists(ctx, dms.ID)
	if err != nil || !found || !reflect.DeepEqual(got.Settings, dms.Settings) || !reflect.DeepEqual(got.Metadata, dms.Metadata) || !got.CreationDate.Equal(now) {
		t.Fatalf("DMS round trip: found=%v DMS=%+v error=%v", found, got, err)
	}
	second := *dms
	second.ID = "dms-b"
	if _, err := store.Insert(ctx, &second); err != nil {
		t.Fatal(err)
	}
	params := &resources.QueryParameters{PageSize: 1, Filters: []resources.FilterOption{{Field: "name", FilterOperation: resources.StringEqualIgnoreCase, Value: "GATEWAY"}}}
	if count, err := store.CountWithFilters(ctx, params); err != nil || count != 2 {
		t.Fatalf("DMS count=%d error=%v", count, err)
	}
	var ids []string
	bookmark, err := store.SelectAll(ctx, false, func(d models.DMS) { ids = append(ids, d.ID) }, params, nil)
	if err != nil || bookmark == "" {
		t.Fatalf("DMS first page: bookmark=%q error=%v", bookmark, err)
	}
	params.NextBookmark = bookmark
	bookmark, err = store.SelectAll(ctx, false, func(d models.DMS) { ids = append(ids, d.ID) }, params, nil)
	if err != nil || bookmark != "" || !reflect.DeepEqual(ids, []string{"dms-a", "dms-b"}) {
		t.Fatalf("DMS pages=%v bookmark=%q error=%v", ids, bookmark, err)
	}
	params.NextBookmark = ""
	ids = nil
	var updateErr error
	_, err = store.SelectAll(ctx, true, func(d models.DMS) {
		ids = append(ids, d.ID)
		d.Name = "processed"
		if _, err := store.Update(ctx, &d); err != nil {
			updateErr = err
		}
	}, params, nil)
	if err != nil || updateErr != nil || !reflect.DeepEqual(ids, []string{"dms-a", "dms-b"}) {
		t.Fatalf("DMS exhaustive=%v error=%v update=%v", ids, err, updateErr)
	}
	if err := store.Delete(ctx, dms.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, second.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, second.ID); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("missing DMS: %v", err)
	}
}
