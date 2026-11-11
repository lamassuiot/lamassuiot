package oracle

import (
	"context"
	"crypto/x509"
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

type vaContractRepositories struct {
	name string
	db   *gorm.DB
	kms  storage.KMSKeysRepo
	cert storage.CertificatesRepo
	va   storage.VARepo
}

func testVARepositoryContracts(t *testing.T, ctx context.Context, repos ...vaContractRepositories) {
	t.Helper()
	version, ok := new(big.Int).SetString("12345678901234567890123456789012345678901234567890", 10)
	if !ok {
		t.Fatal("invalid test CRL version")
	}
	now := time.Now().UTC().Truncate(time.Second)

	for _, repo := range repos {
		t.Run(repo.name, func(t *testing.T) {
			key := &models.Key{
				KeyID: "oracle-contract-va-key", EngineID: "oracle-contract-va-engine", Name: "va-contract-key",
				HasPrivateKey: true, Algorithm: "RSA", Size: 2048, PublicKey: "va-contract-public-key", CreationTS: now,
				Aliases: []string{}, Tags: []string{}, Metadata: map[string]any{},
			}
			cert := &models.Certificate{
				SerialNumber: "oracle-contract-va-signer", Status: models.StatusActive, Type: models.CertificateTypeManaged,
				EngineID: key.EngineID, KeyID: key.KeyID, IsCA: true, SubjectKeyID: "oracle-contract-va-ski",
				KeyMetadata: models.KeyStrengthMetadata{Type: models.KeyType(x509.RSA), Bits: 2048, Strength: models.KeyStrengthHigh},
				Subject:     models.Subject{CommonName: "va signer"}, Issuer: models.Subject{CommonName: "va issuer"},
				Extensions: models.CertificateExtensions{KeyUsage: 0, ExtendedKeyUsage: []models.X509ExtKeyUsage{}},
				ValidFrom:  now.Add(-time.Hour), ValidTo: now.Add(time.Hour), Metadata: map[string]any{},
			}
			if _, err := repo.kms.Insert(ctx, key); err != nil {
				t.Fatalf("insert signer key: %v", err)
			}
			if _, err := repo.cert.Insert(ctx, cert); err != nil {
				t.Fatalf("insert signer certificate: %v", err)
			}
			t.Cleanup(func() {
				_ = repo.db.WithContext(context.Background()).Exec("DELETE FROM va_role WHERE ca_ski IN (?, ?)", "oracle-contract-va-ski-a", "oracle-contract-va-ski-b").Error
				_ = repo.cert.Delete(context.Background(), cert.SerialNumber)
				_ = repo.kms.Delete(context.Background(), key.KeyID, key.EngineID)
			})

			role := &models.VARole{
				CASubjectKeyID: "oracle-contract-va-ski-a",
				CRLOptions: models.VACRLRole{
					RefreshInterval: models.TimeDuration(time.Hour), Validity: models.TimeDuration(24 * time.Hour),
					SignerCertificateSerialNumber: cert.SerialNumber, RegenerateOnRevoke: true,
				},
				LatestCRL: models.LatestCRLMeta{Version: models.BigInt{Int: version}, ValidFrom: now, ValidUntil: now.Add(time.Hour)},
			}
			if _, err := repo.va.Insert(ctx, role); err != nil {
				t.Fatalf("insert VA role: %v", err)
			}
			if _, err := repo.va.Insert(ctx, role); !errors.Is(err, gorm.ErrDuplicatedKey) {
				t.Fatalf("duplicate VA role error = %v", err)
			}
			found, stored, err := repo.va.Get(ctx, role.CASubjectKeyID)
			if err != nil || !found || stored.LatestCRL.Version.Int.Cmp(version) != 0 || stored.CRLOptions.RefreshInterval != role.CRLOptions.RefreshInterval || !stored.CRLOptions.RegenerateOnRevoke {
				t.Fatalf("VA round trip found=%v role=%+v error=%v", found, stored, err)
			}
			if found, _, err := repo.va.Get(ctx, "oracle-contract-va-missing"); err != nil || found {
				t.Fatalf("missing VA role found=%v error=%v", found, err)
			}
			if err := repo.cert.Delete(ctx, cert.SerialNumber); !errors.Is(err, errs.ErrCertificateInUse) {
				t.Fatalf("signer certificate delete error = %v", err)
			}
			bad := *role
			bad.CASubjectKeyID = "oracle-contract-va-bad-ski"
			bad.CRLOptions.SignerCertificateSerialNumber = "oracle-contract-va-missing-signer"
			if _, err := repo.va.Insert(ctx, &bad); !errors.Is(err, errs.ErrCertificateNotFound) {
				t.Fatalf("missing signer error = %v", err)
			}
			role.CRLOptions.RegenerateOnRevoke = false
			if _, err := repo.va.Update(ctx, role); err != nil {
				t.Fatalf("update VA role: %v", err)
			}
			_, stored, err = repo.va.Get(ctx, role.CASubjectKeyID)
			if err != nil || stored.CRLOptions.RegenerateOnRevoke {
				t.Fatalf("updated VA role=%+v error=%v", stored, err)
			}

			second := *role
			second.CASubjectKeyID = "oracle-contract-va-ski-b"
			if _, err := repo.va.Insert(ctx, &second); err != nil {
				t.Fatalf("insert second VA role: %v", err)
			}
			params := &resources.QueryParameters{PageSize: 1}
			var ids []string
			req := storage.StorageListRequest[models.VARole]{QueryParams: params, ApplyFunc: func(item models.VARole) { ids = append(ids, item.CASubjectKeyID) }}
			bookmark, err := repo.va.GetAll(ctx, req)
			if err != nil || bookmark == "" {
				t.Fatalf("first VA page bookmark=%q error=%v", bookmark, err)
			}
			params.NextBookmark = bookmark
			bookmark, err = repo.va.GetAll(ctx, req)
			if err != nil || bookmark != "" || !reflect.DeepEqual(ids, []string{"oracle-contract-va-ski-a", "oracle-contract-va-ski-b"}) {
				t.Fatalf("VA pages=%v bookmark=%q error=%v", ids, bookmark, err)
			}
		})
	}
}
