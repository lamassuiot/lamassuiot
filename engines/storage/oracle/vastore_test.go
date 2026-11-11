package oracle

import (
	"context"
	"errors"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"gorm.io/gorm"
)

func testVARoles(t *testing.T, ctx context.Context, db *gorm.DB, certs *certificateStore, now time.Time) {
	t.Helper()
	store := &vaStore{db: db}
	version, ok := new(big.Int).SetString("12345678901234567890123456789012345678901234567890", 10)
	if !ok {
		t.Fatal("invalid test version")
	}
	role := &models.VARole{CASubjectKeyID: "ski-a", CRLOptions: models.VACRLRole{RefreshInterval: models.TimeDuration(time.Hour), Validity: models.TimeDuration(24 * time.Hour), SignerCertificateSerialNumber: "two", RegenerateOnRevoke: true}, LatestCRL: models.LatestCRLMeta{Version: models.BigInt{Int: version}, ValidFrom: now, ValidUntil: now.Add(time.Hour)}}
	if _, err := store.Insert(ctx, role); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Insert(ctx, role); !errors.Is(err, gorm.ErrDuplicatedKey) {
		t.Fatalf("duplicate VA role: %v", err)
	}
	found, stored, err := store.Get(ctx, role.CASubjectKeyID)
	if err != nil || !found || stored.LatestCRL.Version.Int.Cmp(version) != 0 || stored.CRLOptions.RefreshInterval != role.CRLOptions.RefreshInterval || !stored.CRLOptions.RegenerateOnRevoke {
		t.Fatalf("VA round trip: found=%v role=%+v error=%v", found, stored, err)
	}
	if err := certs.Delete(ctx, "two"); !errors.Is(err, errs.ErrCertificateInUse) {
		t.Fatalf("signer delete: %v", err)
	}
	bad := *role
	bad.CASubjectKeyID = "missing-signer"
	bad.CRLOptions.SignerCertificateSerialNumber = "missing"
	if _, err := store.Insert(ctx, &bad); !errors.Is(err, errs.ErrCertificateNotFound) {
		t.Fatalf("missing signer: %v", err)
	}
	role.CRLOptions.RegenerateOnRevoke = false
	if _, err := store.Update(ctx, role); err != nil {
		t.Fatal(err)
	}
	_, stored, err = store.Get(ctx, role.CASubjectKeyID)
	if err != nil || stored.CRLOptions.RegenerateOnRevoke {
		t.Fatalf("VA update: %+v error=%v", stored, err)
	}
	second := *role
	second.CASubjectKeyID = "ski-b"
	if _, err := store.Insert(ctx, &second); err != nil {
		t.Fatal(err)
	}
	params := &resources.QueryParameters{PageSize: 1}
	var ids []string
	req := storage.StorageListRequest[models.VARole]{QueryParams: params, ApplyFunc: func(r models.VARole) { ids = append(ids, r.CASubjectKeyID) }}
	bookmark, err := store.GetAll(ctx, req)
	if err != nil || bookmark == "" {
		t.Fatalf("VA first page: bookmark=%q error=%v", bookmark, err)
	}
	params.NextBookmark = bookmark
	bookmark, err = store.GetAll(ctx, req)
	if err != nil || bookmark != "" || !reflect.DeepEqual(ids, []string{"ski-a", "ski-b"}) {
		t.Fatalf("VA pages=%v bookmark=%q error=%v", ids, bookmark, err)
	}
	if err := db.WithContext(ctx).Exec("DELETE FROM va_role WHERE ca_ski IN (?, ?)", role.CASubjectKeyID, second.CASubjectKeyID).Error; err != nil {
		t.Fatal(err)
	}
}
