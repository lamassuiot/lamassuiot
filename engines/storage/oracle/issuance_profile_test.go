package oracle

import (
	"context"
	"crypto/x509"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"gorm.io/gorm"
)

// Called against the same freshly migrated disposable schema as the KMS tests.
func testIssuanceProfiles(t *testing.T, ctx context.Context, db *gorm.DB) {
	t.Helper()
	store := &issuanceProfileStore{db: db}
	profile := &models.IssuanceProfile{
		ID: "profile-a", Name: "profile", Description: strings.Repeat("profile text ", 600),
		Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(24 * time.Hour), Time: time.Now().UTC().Truncate(time.Second)},
		SignAsCA: true, HonorKeyUsage: true, KeyUsage: models.X509KeyUsage(x509.KeyUsageDigitalSignature),
		HonorExtendedKeyUsages: true, ExtendedKeyUsages: []models.X509ExtKeyUsage{models.X509ExtKeyUsage(x509.ExtKeyUsageClientAuth)},
		HonorSubject: true, Subject: models.Subject{CommonName: "subject"}, HonorExtensions: true,
		CryptoEnforcement: models.IssuanceProfileCryptoEnforcement{Enabled: true, AllowRSAKeys: true, AllowedRSAKeySizes: []int{2048, 4096}, AllowECDSAKeys: true, AllowedECDSAKeySizes: []int{256, 384}},
	}
	if _, err := store.Insert(ctx, profile); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Insert(ctx, profile); !errors.Is(err, gorm.ErrDuplicatedKey) {
		t.Fatalf("duplicate profile: %v", err)
	}
	found, got, err := store.SelectByID(ctx, profile.ID)
	if err != nil || !found || got.Description != profile.Description || got.Validity.Duration != profile.Validity.Duration || got.KeyUsage != profile.KeyUsage || !reflect.DeepEqual(got.CryptoEnforcement.AllowedRSAKeySizes, profile.CryptoEnforcement.AllowedRSAKeySizes) {
		t.Fatalf("profile round trip: found=%v profile=%+v error=%v", found, got, err)
	}
	profile.SignAsCA = false
	profile.CryptoEnforcement.AllowedRSAKeySizes = []int{}
	if _, err := store.Update(ctx, profile); err != nil {
		t.Fatal(err)
	}
	_, got, err = store.SelectByID(ctx, profile.ID)
	if err != nil || got.SignAsCA || len(got.CryptoEnforcement.AllowedRSAKeySizes) != 0 {
		t.Fatalf("profile update: %+v error=%v", got, err)
	}
	second := *profile
	second.ID = "profile-b"
	if _, err := store.Insert(ctx, &second); err != nil {
		t.Fatal(err)
	}
	if count, err := store.Count(ctx); err != nil || count != 2 {
		t.Fatalf("profile count=%d error=%v", count, err)
	}
	params := &resources.QueryParameters{PageSize: 1, Filters: []resources.FilterOption{{Field: "name", FilterOperation: resources.StringEqual, Value: "profile"}}}
	var ids []string
	req := storage.StorageListRequest[models.IssuanceProfile]{QueryParams: params, ApplyFunc: func(p models.IssuanceProfile) { ids = append(ids, p.ID) }}
	bookmark, err := store.SelectAll(ctx, req)
	if err != nil || bookmark == "" {
		t.Fatalf("profile first page: bookmark=%q error=%v", bookmark, err)
	}
	params.NextBookmark = bookmark
	bookmark, err = store.SelectAll(ctx, req)
	if err != nil || bookmark != "" || !reflect.DeepEqual(ids, []string{"profile-a", "profile-b"}) {
		t.Fatalf("profile pages=%v bookmark=%q error=%v", ids, bookmark, err)
	}
	if err := store.Delete(ctx, profile.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, second.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, second.ID); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("missing profile: %v", err)
	}
}
