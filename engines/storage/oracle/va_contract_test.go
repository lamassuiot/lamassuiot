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
)

type vaContractRepositories struct {
	name string
	kms  storage.KMSKeysRepo
	cert storage.CertificatesRepo
	crl  storage.CRLSettingsRepo
}

// testCRLSettingsRepositoryContracts runs the CRL settings contract of the PostgreSQL repository
// (engines/storage/postgres/test/crl_settings_repo_test.go) against every repository given.
func testCRLSettingsRepositoryContracts(t *testing.T, ctx context.Context, repos ...vaContractRepositories) {
	t.Helper()
	// Wider than the 38 digits of an Oracle NUMBER.
	bigVersion, ok := new(big.Int).SetString("12345678901234567890123456789012345678901234567890", 10)
	if !ok {
		t.Fatal("invalid test CRL version")
	}
	now := time.Now().UTC().Truncate(time.Second)
	const prefix = "oracle-contract-crl-"

	for _, repo := range repos {
		t.Run(repo.name, func(t *testing.T) {
			newKey := func(id string) *models.Key {
				key := &models.Key{
					KeyID: prefix + id, EngineID: prefix + "engine", Name: id, HasPrivateKey: true, Algorithm: "RSA",
					Size: 2048, PublicKey: "public-" + id, CreationTS: now, Aliases: []string{}, Tags: []string{}, Metadata: map[string]any{},
				}
				if _, err := repo.kms.Insert(ctx, key); err != nil {
					t.Fatalf("insert key %s: %v", id, err)
				}
				return key
			}
			newSigner := func(id string, key *models.Key) *models.Certificate {
				cert := &models.Certificate{
					SerialNumber: prefix + id, Status: models.StatusActive, Type: models.CertificateTypeManaged,
					EngineID: key.EngineID, KeyID: key.KeyID, IsCA: true, SubjectKeyID: prefix + id + "-ski",
					KeyMetadata: models.KeyStrengthMetadata{Type: models.KeyType(x509.RSA), Bits: 2048, Strength: models.KeyStrengthHigh},
					Subject:     models.Subject{CommonName: id}, Issuer: models.Subject{CommonName: "crl issuer"},
					Extensions: models.CertificateExtensions{ExtendedKeyUsage: []models.X509ExtKeyUsage{}},
					ValidFrom:  now.Add(-time.Hour), ValidTo: now.Add(time.Hour), Metadata: map[string]any{},
				}
				if _, err := repo.cert.Insert(ctx, cert); err != nil {
					t.Fatalf("insert signer %s: %v", id, err)
				}
				return cert
			}
			key1, key2 := newKey("k1"), newKey("k2")
			signer, signer2 := newSigner("s1", key1), newSigner("s2", key2)

			var caIDs []string
			t.Cleanup(func() {
				bg := context.Background()
				for _, id := range caIDs {
					_ = repo.crl.MarkArchived(bg, id)
					_ = repo.crl.Delete(bg, id)
				}
				for _, cert := range []*models.Certificate{signer, signer2} {
					_ = repo.cert.Delete(bg, cert.SerialNumber)
				}
				for _, key := range []*models.Key{key1, key2} {
					_ = repo.kms.Delete(bg, key.KeyID, key.EngineID)
				}
			})

			keyOf := func(cert *models.Certificate) models.CRLSignerKey {
				return models.CRLSignerKey{EngineID: cert.EngineID, KeyID: cert.KeyID}
			}
			settings := func(caID string, legacySKI *string) *models.CRLSettings {
				return &models.CRLSettings{
					CAID: prefix + caID, LegacySKI: legacySKI, Status: models.CRLSettingsActive,
					SignerEngineID: &signer.EngineID, SignerKeyID: &signer.KeyID,
					Options: models.CRLSettingsOptions{
						SignerSerialNumber: signer.SerialNumber, Validity: models.TimeDuration(time.Hour),
						RefreshInterval: models.TimeDuration(30 * time.Minute), RegenerateOnRevoke: true,
					},
					LatestCRL: models.LatestCRLMeta{Version: models.BigInt{Int: big.NewInt(0)}, ValidFrom: now},
				}
			}
			insert := func(caID string, legacySKI *string) {
				t.Helper()
				caIDs = append(caIDs, prefix+caID)
				if _, err := repo.crl.Insert(ctx, settings(caID, legacySKI)); err != nil {
					t.Fatalf("insert CRL settings %s: %v", caID, err)
				}
			}
			get := func(caID string) *models.CRLSettings {
				t.Helper()
				found, s, err := repo.crl.Get(ctx, prefix+caID)
				if err != nil || !found {
					t.Fatalf("get CRL settings %s: found=%v error=%v", caID, found, err)
				}
				return s
			}
			latest := func(v *big.Int) models.LatestCRLMeta {
				return models.LatestCRLMeta{Version: models.BigInt{Int: v}, ValidFrom: now, ValidUntil: now.Add(time.Hour)}
			}
			expectErr := func(what string, err, want error) {
				t.Helper()
				if !errors.Is(err, want) {
					t.Fatalf("%s: error = %v; want %v", what, err, want)
				}
			}

			// Insert and get, by CA id and by legacy SKI.
			ski := prefix + "3f9a"
			insert("a", &ski)
			insert("b", nil)
			a := get("a")
			if a.Status != models.CRLSettingsActive || a.Options.SignerSerialNumber != signer.SerialNumber ||
				a.Options.Validity != models.TimeDuration(time.Hour) || !a.Options.RegenerateOnRevoke ||
				a.LegacySKI == nil || *a.LegacySKI != ski || a.SignerEngineID == nil || *a.SignerEngineID != signer.EngineID ||
				a.SignerKeyID == nil || *a.SignerKeyID != signer.KeyID {
				t.Fatalf("CRL settings round trip: %+v", a)
			}
			if b := get("b"); b.LegacySKI != nil {
				t.Fatalf("settings without legacy SKI: %v", *b.LegacySKI)
			}
			if found, _, err := repo.crl.Get(ctx, prefix+"missing"); err != nil || found {
				t.Fatalf("missing settings: found=%v error=%v", found, err)
			}
			if found, s, err := repo.crl.GetByLegacySKI(ctx, ski); err != nil || !found || s.CAID != prefix+"a" {
				t.Fatalf("by legacy SKI: found=%v settings=%+v error=%v", found, s, err)
			}
			if _, err := repo.crl.Insert(ctx, settings("a", nil)); err == nil {
				t.Fatal("duplicate CA id accepted")
			}
			if _, err := repo.crl.Insert(ctx, settings("c", &ski)); err == nil {
				t.Fatal("duplicate legacy SKI accepted")
			}

			// The signer must be an existing certificate, and ACTIVE settings need its key.
			missingSigner := settings("d", nil)
			missingSigner.Options.SignerSerialNumber = prefix + "missing"
			_, err := repo.crl.Insert(ctx, missingSigner)
			expectErr("insert with missing signer", err, errs.ErrCertificateNotFound)
			_, err = repo.crl.UpdateOptions(ctx, prefix+"a", missingSigner.Options, keyOf(signer))
			expectErr("update to missing signer", err, errs.ErrCertificateNotFound)
			if s := get("a"); s.Options.SignerSerialNumber != signer.SerialNumber {
				t.Fatalf("failed update changed the signer: %s", s.Options.SignerSerialNumber)
			}
			missingKey := settings("e", nil)
			missingKey.SignerKeyID = new(string)
			*missingKey.SignerKeyID = prefix + "absent"
			_, err = repo.crl.Insert(ctx, missingKey)
			expectErr("insert with missing key", err, errs.ErrKeyNotFound)
			noKey := settings("f", nil)
			noKey.SignerKeyID = nil
			_, err = repo.crl.Insert(ctx, noKey)
			expectErr("ACTIVE settings without key", err, errs.ErrValidateBadRequest)

			// Updating the options moves the key with the signer and leaves status and latest CRL alone.
			if err := repo.crl.UpdateLatestCRL(ctx, prefix+"b", big.NewInt(0), latest(bigVersion)); err != nil {
				t.Fatalf("update latest CRL: %v", err)
			}
			opts := settings("b", nil).Options
			opts.Validity = models.TimeDuration(2 * time.Hour)
			opts.RegenerateOnRevoke = false
			opts.SignerSerialNumber = signer2.SerialNumber
			updated, err := repo.crl.UpdateOptions(ctx, prefix+"b", opts, keyOf(signer2))
			if err != nil || updated.Options != opts || updated.Status != models.CRLSettingsActive ||
				updated.LatestCRL.Version.Int.Cmp(bigVersion) != 0 || *updated.SignerKeyID != signer2.KeyID {
				t.Fatalf("update options: %+v error=%v", updated, err)
			}
			_, err = repo.crl.UpdateOptions(ctx, prefix+"nope", opts, keyOf(signer2))
			expectErr("update options of missing settings", err, errs.ErrCRLSettingsNotFound)

			// The latest CRL is compare-and-swap on the version.
			one := big.NewInt(1)
			if err := repo.crl.UpdateLatestCRL(ctx, prefix+"a", big.NewInt(0), latest(one)); err != nil {
				t.Fatalf("update latest CRL: %v", err)
			}
			expectErr("stale latest CRL", repo.crl.UpdateLatestCRL(ctx, prefix+"a", big.NewInt(0), latest(one)), errs.ErrCRLSettingsConflict)
			if v := get("a").LatestCRL.Version.Int; v.Cmp(one) != 0 {
				t.Fatalf("latest CRL version = %s", v)
			}

			// Certificates and keys are retained while referenced; renaming the key moves it in the settings.
			expectErr("delete signer certificate", repo.cert.Delete(ctx, signer.SerialNumber), errs.ErrCertificateInUse)
			holders := func(serials ...string) []string {
				t.Helper()
				got, err := repo.cert.CRLSettingsHoldingKey(ctx, serials)
				if err != nil {
					t.Fatalf("CRL settings holding key: %v", err)
				}
				return got
			}
			if got := holders(signer.SerialNumber, signer2.SerialNumber); !reflect.DeepEqual(got, []string{prefix + "a", prefix + "b"}) {
				t.Fatalf("holders = %v", got)
			}
			if got := holders(); len(got) != 0 {
				t.Fatalf("holders of no certificate = %v", got)
			}
			if err := repo.cert.ReleaseKey(ctx, []string{signer2.SerialNumber}); err != nil {
				t.Fatalf("release key: %v", err)
			}
			expectErr("delete retained key", repo.kms.Delete(ctx, key2.KeyID, key2.EngineID), errs.ErrKeyInUse)
			renamedKeyID := prefix + "k2-renamed"
			if renamed, err := repo.kms.RenameKey(ctx, key2.EngineID, key2.KeyID, renamedKeyID, func() error { return nil }); err != nil || !renamed {
				t.Fatalf("rename signer key: renamed=%v error=%v", renamed, err)
			}
			key2.KeyID = renamedKeyID
			if s := get("b"); s.SignerKeyID == nil || *s.SignerKeyID != renamedKeyID {
				t.Fatalf("settings did not follow the renamed key: %+v", s)
			}

			// Listing pages by CA id and filters by status.
			params := &resources.QueryParameters{PageSize: 1, Filters: []resources.FilterOption{
				{Field: "ca_id", FilterOperation: resources.StringContains, Value: prefix},
				{Field: "status", FilterOperation: resources.StringEqual, Value: string(models.CRLSettingsActive)},
			}}
			var ids []string
			req := storage.StorageListRequest[models.CRLSettings]{QueryParams: params, ApplyFunc: func(s models.CRLSettings) { ids = append(ids, s.CAID) }}
			bookmark, err := repo.crl.GetAll(ctx, req)
			if err != nil || bookmark == "" {
				t.Fatalf("first page: bookmark=%q error=%v", bookmark, err)
			}
			params.NextBookmark = bookmark
			if bookmark, err = repo.crl.GetAll(ctx, req); err != nil || bookmark != "" || !reflect.DeepEqual(ids, []string{prefix + "a", prefix + "b"}) {
				t.Fatalf("pages=%v bookmark=%q error=%v", ids, bookmark, err)
			}

			// FINAL is conditional on the version of the final CRL and stops retaining the key, not the certificate.
			expectErr("final on a stale version", repo.crl.MarkFinal(ctx, prefix+"b", big.NewInt(2)), errs.ErrCRLSettingsConflict)
			if err := repo.crl.MarkFinal(ctx, prefix+"b", bigVersion); err != nil {
				t.Fatalf("mark final: %v", err)
			}
			if s := get("b"); s.Status != models.CRLSettingsFinal || s.SignerEngineID != nil || s.SignerKeyID != nil || s.Options.SignerSerialNumber != signer2.SerialNumber {
				t.Fatalf("final settings: %+v", s)
			}
			if err := repo.crl.MarkFinal(ctx, prefix+"b", nil); err != nil {
				t.Fatalf("retried final: %v", err)
			}
			if got := holders(signer2.SerialNumber); len(got) != 0 {
				t.Fatalf("FINAL settings still hold the key: %v", got)
			}
			_, err = repo.crl.UpdateOptions(ctx, prefix+"b", opts, keyOf(signer2))
			expectErr("options of FINAL settings", err, errs.ErrCRLSettingsNotActive)
			expectErr("latest CRL of FINAL settings", repo.crl.UpdateLatestCRL(ctx, prefix+"b", bigVersion, latest(one)), errs.ErrCRLSettingsNotActive)
			expectErr("delete FINAL settings", repo.crl.Delete(ctx, prefix+"b"), errs.ErrCRLSettingsNotArchived)

			// ARCHIVED releases the certificate, never goes back, and is the only status that can be deleted.
			if err := repo.crl.MarkArchived(ctx, prefix+"b"); err != nil {
				t.Fatalf("mark archived: %v", err)
			}
			if s := get("b"); s.Status != models.CRLSettingsArchived || s.Options.SignerSerialNumber != "" {
				t.Fatalf("archived settings: %+v", s)
			}
			if err := repo.crl.MarkArchived(ctx, prefix+"b"); err != nil {
				t.Fatalf("retried archive: %v", err)
			}
			if err := repo.crl.MarkFinal(ctx, prefix+"b", nil); err != nil || get("b").Status != models.CRLSettingsArchived {
				t.Fatalf("final after archived: error=%v", err)
			}
			expectErr("final of missing settings", repo.crl.MarkFinal(ctx, prefix+"missing", nil), errs.ErrCRLSettingsNotFound)
			expectErr("archive missing settings", repo.crl.MarkArchived(ctx, prefix+"missing"), errs.ErrCRLSettingsNotFound)
			expectErr("delete ACTIVE settings", repo.crl.Delete(ctx, prefix+"a"), errs.ErrCRLSettingsNotArchived)
			expectErr("delete missing settings", repo.crl.Delete(ctx, prefix+"missing"), errs.ErrCRLSettingsNotFound)
			if err := repo.crl.Delete(ctx, prefix+"b"); err != nil {
				t.Fatalf("delete archived settings: %v", err)
			}
			if found, _, err := repo.crl.Get(ctx, prefix+"b"); err != nil || found {
				t.Fatalf("deleted settings: found=%v error=%v", found, err)
			}
			if err := repo.kms.Delete(ctx, key2.KeyID, key2.EngineID); err != nil {
				t.Fatalf("delete key no longer retained: %v", err)
			}
		})
	}
}
