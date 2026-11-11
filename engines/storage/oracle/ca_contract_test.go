package oracle

import (
	"context"
	"crypto/x509"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"gorm.io/gorm"
)

type caContractRepositories struct {
	name string
	kms  storage.KMSKeysRepo
	cert storage.CertificatesRepo
	ca   storage.CACertificatesRepo
}

// testCAAndCertificateContracts exercises the CA/certificate repository
// interfaces against each configured engine using the same rows and expected
// behavior. The Oracle KMS integration test supplies Oracle and, in CI,
// PostgreSQL repositories.
func testCAAndCertificateContracts(t *testing.T, ctx context.Context, repos ...caContractRepositories) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	key := &models.Key{
		KeyID: "oracle-contract-ca-key", EngineID: "oracle-contract-ca-engine", Name: "ca-contract-key", HasPrivateKey: true,
		Algorithm: "RSA", Size: 2048, PublicKey: "ca-contract-public-key", CreationTS: now,
		Aliases: []string{}, Tags: []string{}, Metadata: map[string]any{"contract": true},
	}
	rootSerial, childSerial := "oracle-contract-ca-root-cert", "oracle-contract-ca-child-cert"
	rootID, childID := "oracle-contract-ca-root", "oracle-contract-ca-child"
	makeCertificate := func(serial, commonName string, issuer models.IssuerCAMetadata) *models.Certificate {
		return &models.Certificate{
			SerialNumber: serial, SubjectKeyID: serial + "-ski", AuthorityKeyID: issuer.SN,
			Metadata: map[string]any{"contract": true}, Status: models.StatusActive,
			KeyMetadata: models.KeyStrengthMetadata{Type: models.KeyType(x509.RSA), Bits: 2048, Strength: models.KeyStrengthHigh},
			Subject:     models.Subject{CommonName: commonName, Organization: "Lamassu", Country: "ES"},
			Issuer:      models.Subject{CommonName: "contract issuer", Organization: "Lamassu", Country: "ES"},
			Extensions:  models.CertificateExtensions{KeyUsage: 0, ExtendedKeyUsage: []models.X509ExtKeyUsage{}},
			ValidFrom:   now.Add(-time.Hour), ValidTo: now.Add(time.Hour), Type: models.CertificateTypeManaged,
			EngineID: key.EngineID, KeyID: key.KeyID, IsCA: true, IssuerCAMetadata: issuer,
		}
	}
	rootCert := makeCertificate(rootSerial, "root-contract", models.IssuerCAMetadata{})
	childCert := makeCertificate(childSerial, "child-contract", models.IssuerCAMetadata{ID: rootID, SN: rootSerial, Level: 1})
	childCert.Issuer = rootCert.Subject
	childCert.AuthorityKeyID = rootCert.SubjectKeyID
	makeCA := func(id, serial string, level int) *models.CACertificate {
		return &models.CACertificate{ID: id, CertificateSerialNumber: serial, Metadata: map[string]any{"ca": id}, CreationTS: now, Level: level, ProfileID: "profile-contract"}
	}
	rootCA, childCA := makeCA(rootID, rootSerial, 0), makeCA(childID, childSerial, 1)

	for _, repo := range repos {
		t.Run(repo.name, func(t *testing.T) {
			if _, err := repo.kms.Insert(ctx, key); err != nil {
				t.Fatalf("insert KMS key: %v", err)
			}
			t.Cleanup(func() {
				_ = repo.ca.Delete(context.Background(), childID)
				_ = repo.ca.Delete(context.Background(), rootID)
				_ = repo.cert.Delete(context.Background(), childSerial)
				_ = repo.cert.Delete(context.Background(), rootSerial)
				_ = repo.kms.Delete(context.Background(), key.KeyID, key.EngineID)
			})

			for _, cert := range []*models.Certificate{rootCert, childCert} {
				if _, err := repo.cert.Insert(ctx, cert); err != nil {
					t.Fatalf("insert certificate %s: %v", cert.SerialNumber, err)
				}
			}
			if _, err := repo.cert.Insert(ctx, rootCert); !errors.Is(err, errs.ErrCertificateAlreadyExists) {
				t.Fatalf("duplicate certificate error = %v", err)
			}
			missingKeyCert := *rootCert
			missingKeyCert.SerialNumber = "oracle-contract-missing-key-cert"
			missingKeyCert.KeyID = "missing-key"
			if _, err := repo.cert.Insert(ctx, &missingKeyCert); !errors.Is(err, errs.ErrKeyNotFound) {
				t.Fatalf("missing KMS key error = %v", err)
			}
			for _, ca := range []*models.CACertificate{rootCA, childCA} {
				if _, err := repo.ca.Insert(ctx, ca); err != nil {
					t.Fatalf("insert CA %s: %v", ca.ID, err)
				}
			}
			if _, err := repo.ca.Insert(ctx, rootCA); !errors.Is(err, errs.ErrCAAlreadyExists) {
				t.Fatalf("duplicate CA error = %v", err)
			}

			if n, err := repo.cert.Count(ctx); err != nil || n != 2 {
				t.Fatalf("certificate count=%d error=%v", n, err)
			}
			if n, err := repo.cert.CountWithFilters(ctx, &resources.QueryParameters{Filters: []resources.FilterOption{{Field: "status", FilterOperation: resources.EnumEqual, Value: string(models.StatusActive)}}}); err != nil || n != 2 {
				t.Fatalf("filtered certificate count=%d error=%v", n, err)
			}
			if n, err := repo.cert.CountByCA(ctx, rootID); err != nil || n != 1 {
				t.Fatalf("certificates by CA count=%d error=%v", n, err)
			}
			if n, err := repo.cert.CountByCAIDAndStatus(ctx, rootID, models.StatusActive); err != nil || n != 1 {
				t.Fatalf("certificates by CA/status count=%d error=%v", n, err)
			}
			if n, err := repo.cert.CountByCAIDWithFilters(ctx, rootID, &resources.QueryParameters{Filters: []resources.FilterOption{{Field: "subject_common_name", FilterOperation: resources.StringEqual, Value: "child-contract"}}}); err != nil || n != 1 {
				t.Fatalf("filtered certificates by CA count=%d error=%v", n, err)
			}
			if found, got, err := repo.cert.SelectExistsBySerialNumber(ctx, rootSerial); err != nil || !found || got.SerialNumber != rootSerial || got.Status != models.StatusActive || !got.HasPrivateKey {
				t.Fatalf("certificate exists=%v value=%+v error=%v", found, got, err)
			}
			if found, _, err := repo.cert.SelectExistsBySerialNumber(ctx, "oracle-contract-no-cert"); err != nil || found {
				t.Fatalf("missing certificate exists=%v error=%v", found, err)
			}
			for name, testCase := range map[string]struct {
				selectFn func(storage.StorageListRequest[models.Certificate]) (string, error)
				want     int
			}{
				"all": {func(req storage.StorageListRequest[models.Certificate]) (string, error) {
					return repo.cert.SelectAll(ctx, req)
				}, 2},
				"by CA": {func(req storage.StorageListRequest[models.Certificate]) (string, error) {
					return repo.cert.SelectByCA(ctx, rootID, req)
				}, 1},
				"by CA and status": {func(req storage.StorageListRequest[models.Certificate]) (string, error) {
					return repo.cert.SelectByCAIDAndStatus(ctx, rootID, models.StatusActive, req)
				}, 1},
				"by status": {func(req storage.StorageListRequest[models.Certificate]) (string, error) {
					return repo.cert.SelectByStatus(ctx, models.StatusActive, req)
				}, 2},
				"by expiration": {func(req storage.StorageListRequest[models.Certificate]) (string, error) {
					return repo.cert.SelectByExpirationDate(ctx, now.Add(2*time.Hour), now.Add(-2*time.Hour), req)
				}, 2},
			} {
				var serials []string
				if _, err := testCase.selectFn(storage.StorageListRequest[models.Certificate]{ApplyFunc: func(cert models.Certificate) { serials = append(serials, cert.SerialNumber) }}); err != nil || len(serials) != testCase.want {
					t.Errorf("select certificates %s: serials=%v error=%v", name, serials, err)
				}
			}
			certPageParams := &resources.QueryParameters{PageSize: 1, Sort: resources.SortOptions{SortField: "serial_number", SortMode: resources.SortModeAsc}}
			var certPages []string
			certPageReq := storage.StorageListRequest[models.Certificate]{QueryParams: certPageParams, ApplyFunc: func(cert models.Certificate) { certPages = append(certPages, cert.SerialNumber) }}
			bookmark, err := repo.cert.SelectAll(ctx, certPageReq)
			if err != nil || bookmark == "" {
				t.Fatalf("first certificate page bookmark=%q error=%v", bookmark, err)
			}
			certPageParams.NextBookmark = bookmark
			bookmark, err = repo.cert.SelectAll(ctx, certPageReq)
			if err != nil || bookmark != "" || !reflect.DeepEqual(certPages, []string{childSerial, rootSerial}) {
				t.Fatalf("certificate pages=%v bookmark=%q error=%v", certPages, bookmark, err)
			}

			updatedChild := *childCert
			updatedChild.Status = models.StatusRevoked
			if _, err := repo.cert.Update(ctx, &updatedChild); err != nil {
				t.Fatalf("update child certificate: %v", err)
			}
			missingUpdate := updatedChild
			missingUpdate.SerialNumber = "oracle-contract-no-cert"
			if _, err := repo.cert.Update(ctx, &missingUpdate); repo.name == "oracle" && !errors.Is(err, gorm.ErrRecordNotFound) {
				t.Fatalf("update missing certificate: %v", err)
			} else if repo.name == "postgres" && err != nil {
				t.Fatalf("PostgreSQL update missing certificate: %v", err)
			}
			if n, err := repo.cert.CountByCAIDAndStatus(ctx, rootID, models.StatusRevoked); err != nil || n != 1 {
				t.Fatalf("revoked certificates by CA count=%d error=%v", n, err)
			}
			if err := repo.cert.ReleaseKey(ctx, []string{childSerial}); err != nil {
				t.Fatalf("release child KMS key: %v", err)
			}
			if found, cert, err := repo.cert.SelectExistsBySerialNumber(ctx, childSerial); err != nil || !found || cert.KeyID != "" || cert.HasPrivateKey {
				t.Fatalf("released certificate=%+v exists=%v error=%v", cert, found, err)
			}
			if err := repo.cert.ReleaseKey(ctx, nil); err != nil {
				t.Fatalf("release empty certificate set: %v", err)
			}

			if n, err := repo.ca.Count(ctx); err != nil || n != 2 {
				t.Fatalf("CA count=%d error=%v", n, err)
			}
			for name, countFn := range map[string]func() (int, error){
				"filters": func() (int, error) {
					return repo.ca.CountWithFilters(ctx, &resources.QueryParameters{Filters: []resources.FilterOption{{Field: "id", FilterOperation: resources.StringEqual, Value: rootID}}})
				},
				"engine": func() (int, error) { return repo.ca.CountByEngine(ctx, key.EngineID) },
				"engine with filters": func() (int, error) {
					return repo.ca.CountByEngineWithFilters(ctx, key.EngineID, &resources.QueryParameters{Filters: []resources.FilterOption{{Field: "id", FilterOperation: resources.StringEqual, Value: rootID}}})
				},
				"status": func() (int, error) { return repo.ca.CountByStatus(ctx, models.StatusActive) },
			} {
				n, err := countFn()
				want := 2
				if name == "status" || name == "filters" || name == "engine with filters" {
					want = 1
				}
				if err != nil || n != want {
					t.Errorf("CA count %s=%d error=%v", name, n, err)
				}
			}
			if found, ca, err := repo.ca.SelectExistsByID(ctx, rootID); err != nil || !found || ca.CertificateSerialNumber != rootSerial || ca.Certificate.SerialNumber != rootSerial {
				t.Fatalf("CA exists=%v value=%+v error=%v", found, ca, err)
			}
			if found, ca, err := repo.ca.SelectExistsBySerialNumber(ctx, childSerial); err != nil || !found || ca.ID != childID {
				t.Fatalf("CA by serial exists=%v value=%+v error=%v", found, ca, err)
			}
			if found, _, err := repo.ca.SelectExistsByID(ctx, "oracle-contract-no-ca"); err != nil || found {
				t.Fatalf("missing CA exists=%v error=%v", found, err)
			}
			for name, testCase := range map[string]struct {
				selectFn func(storage.StorageListRequest[models.CACertificate]) (string, error)
				want     int
			}{
				"all": {func(req storage.StorageListRequest[models.CACertificate]) (string, error) {
					return repo.ca.SelectAll(ctx, req)
				}, 2},
				"by type": {func(req storage.StorageListRequest[models.CACertificate]) (string, error) {
					return repo.ca.SelectByType(ctx, models.CertificateTypeManaged, req)
				}, 2},
				"by common name": {func(req storage.StorageListRequest[models.CACertificate]) (string, error) {
					return repo.ca.SelectByCommonName(ctx, "child-contract", req)
				}, 1},
				"by parent CA": {func(req storage.StorageListRequest[models.CACertificate]) (string, error) {
					return repo.ca.SelectByParentCA(ctx, rootID, req)
				}, 1},
				"by subject and SKID": {func(req storage.StorageListRequest[models.CACertificate]) (string, error) {
					return repo.ca.SelectBySubjectAndSubjectKeyID(ctx, rootCert.Subject, rootCert.SubjectKeyID, req)
				}, 1},
				"by issuer and AKID": {func(req storage.StorageListRequest[models.CACertificate]) (string, error) {
					return repo.ca.SelectByIssuerAndAuthorityKeyID(ctx, rootCert.Subject, rootCert.SubjectKeyID, req)
				}, 1},
			} {
				var ids []string
				if _, err := testCase.selectFn(storage.StorageListRequest[models.CACertificate]{ApplyFunc: func(ca models.CACertificate) { ids = append(ids, ca.ID) }}); err != nil || len(ids) != testCase.want {
					t.Errorf("select CAs %s: ids=%v error=%v", name, ids, err)
				}
			}
			caPageParams := &resources.QueryParameters{PageSize: 1, Sort: resources.SortOptions{SortField: "id", SortMode: resources.SortModeAsc}}
			var caPages []string
			caPageReq := storage.StorageListRequest[models.CACertificate]{QueryParams: caPageParams, ApplyFunc: func(ca models.CACertificate) { caPages = append(caPages, ca.ID) }}
			bookmark, err = repo.ca.SelectAll(ctx, caPageReq)
			if err != nil || bookmark == "" {
				t.Fatalf("first CA page bookmark=%q error=%v", bookmark, err)
			}
			caPageParams.NextBookmark = bookmark
			bookmark, err = repo.ca.SelectAll(ctx, caPageReq)
			if err != nil || bookmark != "" || !reflect.DeepEqual(caPages, []string{childID, rootID}) {
				t.Fatalf("CA pages=%v bookmark=%q error=%v", caPages, bookmark, err)
			}

			updatedCA := *childCA
			updatedCA.ProfileID = "updated-contract-profile"
			updatedCA.Metadata = map[string]any{"updated": true}
			updatedCA.Certificate.Status = models.StatusInactive
			if _, err := repo.ca.Update(ctx, &updatedCA); err != nil {
				t.Fatalf("update child CA: %v", err)
			}
			if found, ca, err := repo.ca.SelectExistsByID(ctx, childID); err != nil || !found || ca.ProfileID != updatedCA.ProfileID || !reflect.DeepEqual(ca.Metadata, updatedCA.Metadata) {
				t.Fatalf("updated CA=%+v found=%v error=%v", ca, found, err)
			}
			if found, cert, err := repo.cert.SelectExistsBySerialNumber(ctx, childSerial); err != nil || !found || cert.Status != models.StatusRevoked {
				t.Fatalf("updating CA changed its certificate: found=%v cert=%+v error=%v", found, cert, err)
			}
			if err := repo.ca.Delete(ctx, childID); err != nil {
				t.Fatalf("delete child CA: %v", err)
			}
			if err := repo.ca.Delete(ctx, childID); !errors.Is(err, gorm.ErrRecordNotFound) {
				t.Fatalf("delete missing CA: %v", err)
			}
			if found, cert, err := repo.cert.SelectExistsBySerialNumber(ctx, childSerial); err != nil || !found || cert.Status != models.StatusRevoked {
				t.Fatalf("deleting CA changed its certificate: found=%v cert=%+v error=%v", found, cert, err)
			}
			if err := repo.cert.Delete(ctx, childSerial); err != nil {
				t.Fatalf("delete child certificate: %v", err)
			}
			if found, _, err := repo.ca.SelectExistsByID(ctx, childID); err != nil || found {
				t.Fatalf("CA remained after certificate delete: found=%v error=%v", found, err)
			}
			if err := repo.ca.Delete(ctx, rootID); err != nil {
				t.Fatalf("delete root CA: %v", err)
			}
			if err := repo.cert.Delete(ctx, rootSerial); err != nil {
				t.Fatalf("delete root certificate: %v", err)
			}
			if err := repo.cert.Delete(ctx, rootSerial); !errors.Is(err, gorm.ErrRecordNotFound) {
				t.Fatalf("delete missing certificate: %v", err)
			}

			emptySubjectSerial, emptySubjectID := "oracle-contract-empty-subject-cert", "oracle-contract-empty-subject-ca"
			t.Cleanup(func() {
				_ = repo.ca.Delete(context.Background(), emptySubjectID)
				_ = repo.cert.Delete(context.Background(), emptySubjectSerial)
			})
			emptySubjectCert := makeCertificate(emptySubjectSerial, "", models.IssuerCAMetadata{})
			if _, err := repo.cert.Insert(ctx, emptySubjectCert); err != nil {
				t.Fatalf("insert empty-subject certificate: %v", err)
			}
			if _, err := repo.ca.Insert(ctx, makeCA(emptySubjectID, emptySubjectSerial, 0)); err != nil {
				t.Fatalf("insert empty-subject CA: %v", err)
			}
			var emptySubjectMatches []string
			if _, err := repo.ca.SelectByCommonName(ctx, "", storage.StorageListRequest[models.CACertificate]{
				ApplyFunc: func(ca models.CACertificate) { emptySubjectMatches = append(emptySubjectMatches, ca.ID) },
			}); err != nil || !reflect.DeepEqual(emptySubjectMatches, []string{emptySubjectID}) {
				t.Fatalf("empty common-name CAs=%v error=%v", emptySubjectMatches, err)
			}
			if err := repo.ca.Delete(ctx, emptySubjectID); err != nil {
				t.Fatalf("delete empty-subject CA: %v", err)
			}
			if err := repo.cert.Delete(ctx, emptySubjectSerial); err != nil {
				t.Fatalf("delete empty-subject certificate: %v", err)
			}
		})
	}
}
