package catokms

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	log "github.com/sirupsen/logrus"
)

// ---------------------------------------------------------------------------
// Package-level signing key (generated once; shared across all test certs)
// ---------------------------------------------------------------------------

var (
	testSignerOnce sync.Once
	testSigner     *rsa.PrivateKey
)

func getTestSigner() *rsa.PrivateKey {
	testSignerOnce.Do(func() {
		var err error
		testSigner, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic("could not generate test signing key: " + err.Error())
		}
	})
	return testSigner
}

// ---------------------------------------------------------------------------
// Mock storage implementations
// ---------------------------------------------------------------------------

// mockCACertStorage implements storage.CACertificatesRepo.
// Only SelectByType is used by collectKeys; all other methods are no-ops.
type mockCACertStorage struct {
	certs   []models.CACertificate
	listErr error // optional error returned by SelectByType
}

func (m *mockCACertStorage) SelectByType(_ context.Context, caType models.CertificateType, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	if m.listErr != nil {
		return "", m.listErr
	}
	for _, ca := range m.certs {
		if ca.Certificate.Type == caType {
			req.ApplyFunc(ca)
		}
	}
	return "", nil
}

func (m *mockCACertStorage) Count(_ context.Context) (int, error) { return 0, nil }
func (m *mockCACertStorage) CountWithFilters(_ context.Context, _ *resources.QueryParameters) (int, error) {
	return 0, nil
}
func (m *mockCACertStorage) CountByEngine(_ context.Context, _ string) (int, error) { return 0, nil }
func (m *mockCACertStorage) CountByEngineWithFilters(_ context.Context, _ string, _ *resources.QueryParameters) (int, error) {
	return 0, nil
}
func (m *mockCACertStorage) CountByStatus(_ context.Context, _ models.CertificateStatus) (int, error) {
	return 0, nil
}
func (m *mockCACertStorage) SelectAll(_ context.Context, _ storage.StorageListRequest[models.CACertificate]) (string, error) {
	return "", nil
}
func (m *mockCACertStorage) SelectExistsByID(_ context.Context, _ string) (bool, *models.CACertificate, error) {
	return false, nil, nil
}
func (m *mockCACertStorage) SelectExistsBySerialNumber(_ context.Context, _ string) (bool, *models.CACertificate, error) {
	return false, nil, nil
}
func (m *mockCACertStorage) SelectByCommonName(_ context.Context, _ string, _ storage.StorageListRequest[models.CACertificate]) (string, error) {
	return "", nil
}
func (m *mockCACertStorage) SelectByParentCA(_ context.Context, _ string, _ storage.StorageListRequest[models.CACertificate]) (string, error) {
	return "", nil
}
func (m *mockCACertStorage) SelectBySubjectAndSubjectKeyID(_ context.Context, _ models.Subject, _ string, _ storage.StorageListRequest[models.CACertificate]) (string, error) {
	return "", nil
}
func (m *mockCACertStorage) SelectByIssuerAndAuthorityKeyID(_ context.Context, _ models.Subject, _ string, _ storage.StorageListRequest[models.CACertificate]) (string, error) {
	return "", nil
}
func (m *mockCACertStorage) Insert(_ context.Context, ca *models.CACertificate) (*models.CACertificate, error) {
	return ca, nil
}
func (m *mockCACertStorage) Update(_ context.Context, ca *models.CACertificate) (*models.CACertificate, error) {
	return ca, nil
}
func (m *mockCACertStorage) Delete(_ context.Context, _ string) error { return nil }

// mockKMSStorage implements storage.KMSKeysRepo.
// SelectExistsByKeyID and Insert are the only methods exercised by runMigration.
type mockKMSStorage struct {
	existing  map[string]*models.Key // pre-populated; simulate already-migrated keys
	inserted  []*models.Key          // records inserted during test
	insertErr error                  // optional error returned by Insert
	existsErr error                  // optional error returned by SelectExistsByKeyID
}

func newMockKMSStorage() *mockKMSStorage {
	return &mockKMSStorage{existing: map[string]*models.Key{}}
}

func (m *mockKMSStorage) SelectExistsByKeyID(_ context.Context, id string) (bool, *models.Key, error) {
	if m.existsErr != nil {
		return false, nil, m.existsErr
	}
	k, ok := m.existing[id]
	return ok, k, nil
}

func (m *mockKMSStorage) Insert(_ context.Context, key *models.Key) (*models.Key, error) {
	if m.insertErr != nil {
		return nil, m.insertErr
	}
	m.existing[key.KeyID] = key
	m.inserted = append(m.inserted, key)
	return key, nil
}

func (m *mockKMSStorage) Count(_ context.Context) (int, error) { return 0, nil }
func (m *mockKMSStorage) CountWithFilters(_ context.Context, _ *resources.QueryParameters) (int, error) {
	return 0, nil
}
func (m *mockKMSStorage) CountByEngineWithFilters(_ context.Context, _ string, _ *resources.QueryParameters) (int, error) {
	return 0, nil
}
func (m *mockKMSStorage) SelectAll(_ context.Context, _ storage.StorageListRequest[models.Key]) (string, error) {
	return "", nil
}
func (m *mockKMSStorage) SelectExistsByAlias(_ context.Context, _ string) (bool, *models.Key, error) {
	return false, nil, nil
}
func (m *mockKMSStorage) Update(_ context.Context, key *models.Key) (*models.Key, error) {
	return key, nil
}
func (m *mockKMSStorage) Delete(_ context.Context, _ string) error { return nil }

// controlledKMSStorage wraps mockKMSStorage but fails Insert after failAfter successful calls.
type controlledKMSStorage struct {
	inner      *mockKMSStorage
	failAfter  int // succeed this many times, then fail
	insertions int
}

func (c *controlledKMSStorage) SelectExistsByKeyID(ctx context.Context, id string) (bool, *models.Key, error) {
	return c.inner.SelectExistsByKeyID(ctx, id)
}
func (c *controlledKMSStorage) Insert(ctx context.Context, key *models.Key) (*models.Key, error) {
	c.insertions++
	if c.insertions > c.failAfter {
		return nil, errors.New("simulated insert failure")
	}
	return c.inner.Insert(ctx, key)
}
func (c *controlledKMSStorage) Count(_ context.Context) (int, error) { return 0, nil }
func (c *controlledKMSStorage) CountWithFilters(_ context.Context, _ *resources.QueryParameters) (int, error) {
	return 0, nil
}
func (c *controlledKMSStorage) CountByEngineWithFilters(_ context.Context, _ string, _ *resources.QueryParameters) (int, error) {
	return 0, nil
}
func (c *controlledKMSStorage) SelectAll(_ context.Context, _ storage.StorageListRequest[models.Key]) (string, error) {
	return "", nil
}
func (c *controlledKMSStorage) SelectExistsByAlias(_ context.Context, _ string) (bool, *models.Key, error) {
	return false, nil, nil
}
func (c *controlledKMSStorage) Update(_ context.Context, key *models.Key) (*models.Key, error) {
	return key, nil
}
func (c *controlledKMSStorage) Delete(_ context.Context, _ string) error { return nil }

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func silentLogger() *log.Entry {
	l := log.New()
	l.SetLevel(log.PanicLevel)
	return log.NewEntry(l)
}

// keyIDFromPub computes SHA-256(PKIX(pub)) and hex-encodes it — same as EncodePKIXPublicKeyDigest.
func keyIDFromPub(t *testing.T, pub any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("keyIDFromPub: %s", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// pubKeyB64PEM encodes pub as base64(PEM "PUBLIC KEY") — the format stored in kms_keys.
func pubKeyB64PEM(t *testing.T, pub any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("pubKeyB64PEM: %s", err)
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return base64.StdEncoding.EncodeToString(block)
}

// makeCACert builds a models.CACertificate for the given public key.
// The cert is signed with a shared test signer so key generation is O(1) per test.
// The certificate's PublicKey field is set to pub so collectKeys extracts it correctly.
func makeCACert(t *testing.T, id, serial, engineID string, certType models.CertificateType, pub any, bits int, keyType models.KeyType, cn string, validFrom time.Time) models.CACertificate {
	t.Helper()

	skid := keyIDFromPub(t, pub)
	signer := getTestSigner()

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    validFrom,
		NotAfter:     validFrom.Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		t.Fatalf("makeCACert CreateCertificate: %s", err)
	}
	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("makeCACert ParseCertificate: %s", err)
	}
	parsedCert.PublicKey = pub // replace with the actual test public key

	return models.CACertificate{
		ID: id,
		Certificate: models.Certificate{
			SerialNumber: serial,
			EngineID:     engineID,
			SubjectKeyID: skid,
			Type:         certType,
			Certificate:  (*models.X509Certificate)(parsedCert),
			KeyMetadata:  models.KeyStrengthMetadata{Type: keyType, Bits: bits},
			Subject:      models.Subject{CommonName: cn},
			ValidFrom:    validFrom,
		},
	}
}

// newRSACACert generates a fresh RSA key and returns a CACertificate using it.
func newRSACACert(t *testing.T, id, serial, engineID string, certType models.CertificateType, bits int, cn string, validFrom time.Time) models.CACertificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("newRSACACert GenerateKey: %s", err)
	}
	return makeCACert(t, id, serial, engineID, certType, key.Public(), bits, models.KeyType(x509.RSA), cn, validFrom)
}

// newECDSACACert generates a fresh ECDSA key and returns a CACertificate using it.
func newECDSACACert(t *testing.T, id, serial, engineID string, certType models.CertificateType, curve elliptic.Curve, cn string, validFrom time.Time) models.CACertificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("newECDSACACert GenerateKey: %s", err)
	}
	return makeCACert(t, id, serial, engineID, certType, key.Public(), curve.Params().BitSize, models.KeyType(x509.ECDSA), cn, validFrom)
}

// newKeyEntryFromRSA builds a keyEntry from a freshly generated RSA key.
func newKeyEntryFromRSA(t *testing.T, engineID, serial, cn string) *keyEntry {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyID := keyIDFromPub(t, key.Public())
	return &keyEntry{
		engineID:   engineID,
		keyID:      keyID,
		algorithm:  "RSA",
		size:       2048,
		publicKey:  pubKeyB64PEM(t, key.Public()),
		name:       cn,
		creationTS: time.Now(),
		serials:    []string{serial},
	}
}

// ---------------------------------------------------------------------------
// collectKeys tests
// ---------------------------------------------------------------------------

func TestCollectKeys_Empty(t *testing.T) {
	keyMap, err := collectKeys(context.Background(), silentLogger(), &mockCACertStorage{})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(keyMap) != 0 {
		t.Fatalf("expected empty map, got %d entries", len(keyMap))
	}
}

func TestCollectKeys_ManagedCert(t *testing.T) {
	ts := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	ca := newRSACACert(t, "ca-1", "serial-1", "engine-a", models.CertificateTypeManaged, 2048, "MyCA", ts)

	keyMap, err := collectKeys(context.Background(), silentLogger(), &mockCACertStorage{certs: []models.CACertificate{ca}})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(keyMap) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keyMap))
	}

	entry := keyMap[ca.Certificate.SubjectKeyID]
	if entry == nil {
		t.Fatal("key entry not found by subject_key_id")
	}
	if entry.engineID != "engine-a" {
		t.Errorf("engineID: got %q, want engine-a", entry.engineID)
	}
	if entry.algorithm != "RSA" {
		t.Errorf("algorithm: got %q, want RSA", entry.algorithm)
	}
	if entry.size != 2048 {
		t.Errorf("size: got %d, want 2048", entry.size)
	}
	if entry.name != "MyCA" {
		t.Errorf("name: got %q, want MyCA", entry.name)
	}
	if !entry.creationTS.Equal(ts) {
		t.Errorf("creationTS: got %v, want %v", entry.creationTS, ts)
	}
	if len(entry.serials) != 1 || entry.serials[0] != "serial-1" {
		t.Errorf("serials: got %v, want [serial-1]", entry.serials)
	}
	if entry.publicKey == "" {
		t.Error("publicKey should not be empty")
	}
	raw, err2 := base64.StdEncoding.DecodeString(entry.publicKey)
	if err2 != nil {
		t.Errorf("publicKey is not valid base64: %s", err2)
	}
	pemBlock, _ := pem.Decode(raw)
	if pemBlock == nil {
		t.Error("publicKey base64 does not contain a valid PEM block")
	}
}

func TestCollectKeys_ImportedWithKeyCert(t *testing.T) {
	ca := newECDSACACert(t, "ca-2", "serial-2", "engine-b", models.CertificateTypeImportedWithKey, elliptic.P256(), "ImportedCA", time.Now())

	keyMap, err := collectKeys(context.Background(), silentLogger(), &mockCACertStorage{certs: []models.CACertificate{ca}})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(keyMap) != 1 {
		t.Fatal("expected 1 key for IMPORTED_WITH_KEY cert")
	}
	entry := keyMap[ca.Certificate.SubjectKeyID]
	if entry.algorithm != "ECDSA" {
		t.Errorf("algorithm: got %q, want ECDSA", entry.algorithm)
	}
	if entry.engineID != "engine-b" {
		t.Errorf("engineID: got %q, want engine-b", entry.engineID)
	}
}

func TestCollectKeys_ImportedWithoutKeyCert_IsSkipped(t *testing.T) {
	ca := newRSACACert(t, "ca-3", "serial-3", "engine-c", models.CertificateTypeImportedWithoutKey, 2048, "NokeyCA", time.Now())

	keyMap, err := collectKeys(context.Background(), silentLogger(), &mockCACertStorage{certs: []models.CACertificate{ca}})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(keyMap) != 0 {
		t.Fatal("IMPORTED_WITHOUT_KEY cert should not appear in key map")
	}
}

func TestCollectKeys_MissingEngineID_IsSkipped(t *testing.T) {
	ca := newRSACACert(t, "ca-4", "serial-4", "", models.CertificateTypeManaged, 2048, "NoEngineCA", time.Now())

	keyMap, err := collectKeys(context.Background(), silentLogger(), &mockCACertStorage{certs: []models.CACertificate{ca}})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(keyMap) != 0 {
		t.Fatal("cert with empty engine_id should be skipped")
	}
}

func TestCollectKeys_MissingSubjectKeyID_IsSkipped(t *testing.T) {
	ca := newRSACACert(t, "ca-5", "serial-5", "engine-a", models.CertificateTypeManaged, 2048, "NoSkidCA", time.Now())
	ca.Certificate.SubjectKeyID = ""

	keyMap, err := collectKeys(context.Background(), silentLogger(), &mockCACertStorage{certs: []models.CACertificate{ca}})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(keyMap) != 0 {
		t.Fatal("cert with empty subject_key_id should be skipped")
	}
}

func TestCollectKeys_NilCertificateBlob_IsSkipped(t *testing.T) {
	ca := newRSACACert(t, "ca-6", "serial-6", "engine-a", models.CertificateTypeManaged, 2048, "NilBlobCA", time.Now())
	ca.Certificate.Certificate = nil

	keyMap, err := collectKeys(context.Background(), silentLogger(), &mockCACertStorage{certs: []models.CACertificate{ca}})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(keyMap) != 0 {
		t.Fatal("cert with nil certificate blob should be skipped")
	}
}

func TestCollectKeys_SharedKey_GroupsBothSerials(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub := key.Public()
	ts := time.Now()

	ca1 := makeCACert(t, "ca-7a", "serial-7a", "engine-a", models.CertificateTypeManaged, pub, 2048, models.KeyType(x509.RSA), "SharedKeyCA1", ts)
	ca2 := makeCACert(t, "ca-7b", "serial-7b", "engine-a", models.CertificateTypeManaged, pub, 2048, models.KeyType(x509.RSA), "SharedKeyCA2", ts)

	keyMap, err := collectKeys(context.Background(), silentLogger(), &mockCACertStorage{certs: []models.CACertificate{ca1, ca2}})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(keyMap) != 1 {
		t.Fatalf("two certs sharing a key should produce 1 entry, got %d", len(keyMap))
	}
	entry := keyMap[ca1.Certificate.SubjectKeyID]
	if len(entry.serials) != 2 {
		t.Errorf("expected 2 serials for shared key, got %d", len(entry.serials))
	}
}

func TestCollectKeys_StorageError_ReturnsError(t *testing.T) {
	caStore := &mockCACertStorage{listErr: errors.New("db read failure")}
	_, err := collectKeys(context.Background(), silentLogger(), caStore)
	if err == nil {
		t.Fatal("expected error when SelectByType fails, got nil")
	}
}

func TestCollectKeys_MixedTypes_OnlyManagedAndImportedWithKey(t *testing.T) {
	managed := newRSACACert(t, "ca-m", "sn-m", "engine-a", models.CertificateTypeManaged, 2048, "Managed", time.Now())
	imported := newRSACACert(t, "ca-i", "sn-i", "engine-a", models.CertificateTypeImportedWithKey, 2048, "Imported", time.Now())
	noKey := newRSACACert(t, "ca-n", "sn-n", "engine-a", models.CertificateTypeImportedWithoutKey, 2048, "NoKey", time.Now())

	keyMap, err := collectKeys(context.Background(), silentLogger(), &mockCACertStorage{certs: []models.CACertificate{managed, imported, noKey}})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(keyMap) != 2 {
		t.Fatalf("expected 2 keys (managed + imported_with_key), got %d", len(keyMap))
	}
}

// ---------------------------------------------------------------------------
// runMigration tests
// ---------------------------------------------------------------------------

func TestRunMigration_InsertsNewKey(t *testing.T) {
	entry := newKeyEntryFromRSA(t, "engine-a", "serial-1", "MyCA")
	kms := newMockKMSStorage()

	ins, skip, fail := runMigration(context.Background(), silentLogger(), kms, map[string]*keyEntry{entry.keyID: entry}, false)

	if ins != 1 || skip != 0 || fail != 0 {
		t.Errorf("counts: ins=%d skip=%d fail=%d, want 1/0/0", ins, skip, fail)
	}
	if len(kms.inserted) != 1 {
		t.Fatal("expected exactly 1 key inserted")
	}

	got := kms.inserted[0]
	if got.KeyID != entry.keyID {
		t.Errorf("KeyID: got %q, want %q", got.KeyID, entry.keyID)
	}
	if got.EngineID != "engine-a" {
		t.Errorf("EngineID: got %q, want engine-a", got.EngineID)
	}
	if got.Algorithm != "RSA" {
		t.Errorf("Algorithm: got %q, want RSA", got.Algorithm)
	}
	if got.Size != 2048 {
		t.Errorf("Size: got %d, want 2048", got.Size)
	}
	if !got.HasPrivateKey {
		t.Error("HasPrivateKey should be true")
	}
	if got.PublicKey != entry.publicKey {
		t.Error("PublicKey field mismatch")
	}

	rawBindings, ok := got.Metadata[models.KMSBindResourceKey]
	if !ok {
		t.Fatalf("metadata missing key %q", models.KMSBindResourceKey)
	}
	bindings, ok := rawBindings.([]models.KMSBindResource)
	if !ok {
		t.Fatalf("metadata[%q] has wrong type %T", models.KMSBindResourceKey, rawBindings)
	}
	if len(bindings) != 1 || bindings[0].ResourceType != "certificate" || bindings[0].ResourceID != "serial-1" {
		t.Errorf("unexpected binded-resources: %+v", bindings)
	}
}

func TestRunMigration_SkipsExistingKey(t *testing.T) {
	entry := newKeyEntryFromRSA(t, "engine-a", "serial-1", "MyCA")
	kms := newMockKMSStorage()
	kms.existing[entry.keyID] = &models.Key{KeyID: entry.keyID}

	ins, skip, fail := runMigration(context.Background(), silentLogger(), kms, map[string]*keyEntry{entry.keyID: entry}, false)

	if ins != 0 || skip != 1 || fail != 0 {
		t.Errorf("counts: ins=%d skip=%d fail=%d, want 0/1/0", ins, skip, fail)
	}
	if len(kms.inserted) != 0 {
		t.Error("no insert should happen for an existing key")
	}
}

func TestRunMigration_InsertError_CountsAsFailed(t *testing.T) {
	entry := newKeyEntryFromRSA(t, "engine-a", "serial-1", "MyCA")
	kms := newMockKMSStorage()
	kms.insertErr = errors.New("write failed")

	ins, skip, fail := runMigration(context.Background(), silentLogger(), kms, map[string]*keyEntry{entry.keyID: entry}, false)

	if ins != 0 || skip != 0 || fail != 1 {
		t.Errorf("counts: ins=%d skip=%d fail=%d, want 0/0/1", ins, skip, fail)
	}
}

func TestRunMigration_CheckExistsError_CountsAsFailed(t *testing.T) {
	entry := newKeyEntryFromRSA(t, "engine-a", "serial-1", "MyCA")
	kms := newMockKMSStorage()
	kms.existsErr = errors.New("db read error")

	ins, skip, fail := runMigration(context.Background(), silentLogger(), kms, map[string]*keyEntry{entry.keyID: entry}, false)

	if ins != 0 || skip != 0 || fail != 1 {
		t.Errorf("counts: ins=%d skip=%d fail=%d, want 0/0/1", ins, skip, fail)
	}
}

func TestRunMigration_DryRun_DoesNotInsert(t *testing.T) {
	entry := newKeyEntryFromRSA(t, "engine-a", "serial-1", "MyCA")
	kms := newMockKMSStorage()

	ins, skip, fail := runMigration(context.Background(), silentLogger(), kms, map[string]*keyEntry{entry.keyID: entry}, true)

	if ins != 1 || skip != 0 || fail != 0 {
		t.Errorf("dry-run counts: ins=%d skip=%d fail=%d, want 1/0/0", ins, skip, fail)
	}
	if len(kms.inserted) != 0 {
		t.Error("dry-run must not write to KMS storage")
	}
}

func TestRunMigration_DryRun_SkipsExistingKey(t *testing.T) {
	entry := newKeyEntryFromRSA(t, "engine-a", "serial-1", "MyCA")
	kms := newMockKMSStorage()
	kms.existing[entry.keyID] = &models.Key{KeyID: entry.keyID}

	ins, skip, fail := runMigration(context.Background(), silentLogger(), kms, map[string]*keyEntry{entry.keyID: entry}, true)

	if ins != 0 || skip != 1 || fail != 0 {
		t.Errorf("dry-run skip counts: ins=%d skip=%d fail=%d, want 0/1/0", ins, skip, fail)
	}
}

func TestRunMigration_Mixed_NewExistingFailed(t *testing.T) {
	newEntry := newKeyEntryFromRSA(t, "engine-a", "new-sn", "NewCA")
	existingEntry := newKeyEntryFromRSA(t, "engine-a", "existing-sn", "ExistingCA")
	failEntry := newKeyEntryFromRSA(t, "engine-a", "fail-sn", "FailCA")

	inner := newMockKMSStorage()
	inner.existing[existingEntry.keyID] = &models.Key{KeyID: existingEntry.keyID}

	kms := &controlledKMSStorage{inner: inner, failAfter: 1}

	keyMap := map[string]*keyEntry{
		newEntry.keyID:      newEntry,
		existingEntry.keyID: existingEntry,
		failEntry.keyID:     failEntry,
	}

	ins, skip, fail := runMigration(context.Background(), silentLogger(), kms, keyMap, false)

	if ins != 1 {
		t.Errorf("expected 1 inserted, got %d", ins)
	}
	if skip != 1 {
		t.Errorf("expected 1 skipped, got %d", skip)
	}
	if fail != 1 {
		t.Errorf("expected 1 failed, got %d", fail)
	}
}

func TestRunMigration_MultipleSerials_AllInBindedResources(t *testing.T) {
	entry := &keyEntry{
		engineID:   "engine-a",
		keyID:      "key-abc",
		algorithm:  "RSA",
		size:       2048,
		publicKey:  "fake-pub",
		name:       "SharedCA",
		creationTS: time.Now(),
		serials:    []string{"sn-1", "sn-2", "sn-3"},
	}
	kms := newMockKMSStorage()

	runMigration(context.Background(), silentLogger(), kms, map[string]*keyEntry{entry.keyID: entry}, false)

	if len(kms.inserted) != 1 {
		t.Fatal("expected exactly 1 insert")
	}
	rawBindings := kms.inserted[0].Metadata[models.KMSBindResourceKey]
	bindings, ok := rawBindings.([]models.KMSBindResource)
	if !ok {
		t.Fatalf("wrong binding type %T", rawBindings)
	}
	if len(bindings) != 3 {
		t.Errorf("expected 3 binded-resources, got %d", len(bindings))
	}
	bySerial := map[string]bool{}
	for _, b := range bindings {
		bySerial[b.ResourceID] = true
		if b.ResourceType != "certificate" {
			t.Errorf("unexpected resource_type %q", b.ResourceType)
		}
	}
	for _, sn := range entry.serials {
		if !bySerial[sn] {
			t.Errorf("serial %q missing from binded-resources", sn)
		}
	}
}

func TestRunMigration_Empty_ZeroCounts(t *testing.T) {
	kms := newMockKMSStorage()
	ins, skip, fail := runMigration(context.Background(), silentLogger(), kms, map[string]*keyEntry{}, false)
	if ins != 0 || skip != 0 || fail != 0 {
		t.Errorf("empty map should give 0/0/0, got %d/%d/%d", ins, skip, fail)
	}
}

func TestRunMigration_Idempotent_SecondRunSkipsAll(t *testing.T) {
	entries := []*keyEntry{
		newKeyEntryFromRSA(t, "engine-a", "sn-1", "CA1"),
		newKeyEntryFromRSA(t, "engine-a", "sn-2", "CA2"),
	}
	keyMap := map[string]*keyEntry{}
	for _, e := range entries {
		keyMap[e.keyID] = e
	}

	kms := newMockKMSStorage()

	ins, skip, fail := runMigration(context.Background(), silentLogger(), kms, keyMap, false)
	if ins != 2 || skip != 0 || fail != 0 {
		t.Errorf("first run: ins=%d skip=%d fail=%d, want 2/0/0", ins, skip, fail)
	}

	ins, skip, fail = runMigration(context.Background(), silentLogger(), kms, keyMap, false)
	if ins != 0 || skip != 2 || fail != 0 {
		t.Errorf("second run: ins=%d skip=%d fail=%d, want 0/2/0", ins, skip, fail)
	}
}

// ---------------------------------------------------------------------------
// Migrate (public API) tests
// ---------------------------------------------------------------------------

func TestMigrate_ReturnsResultStruct(t *testing.T) {
	ca := newRSACACert(t, "ca-1", "serial-1", "engine-a", models.CertificateTypeManaged, 2048, "MyCA", time.Now())
	caStore := &mockCACertStorage{certs: []models.CACertificate{ca}}
	kms := newMockKMSStorage()

	result, err := Migrate(context.Background(), silentLogger(), caStore, kms, false)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if result.Inserted != 1 || result.Skipped != 0 || result.Failed != 0 {
		t.Errorf("result: %+v, want {1 0 0}", result)
	}
}

func TestMigrate_DryRun_ReturnsResultWithoutWriting(t *testing.T) {
	ca := newRSACACert(t, "ca-1", "serial-1", "engine-a", models.CertificateTypeManaged, 2048, "MyCA", time.Now())
	caStore := &mockCACertStorage{certs: []models.CACertificate{ca}}
	kms := newMockKMSStorage()

	result, err := Migrate(context.Background(), silentLogger(), caStore, kms, true)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if result.Inserted != 1 {
		t.Errorf("dry-run inserted count: got %d, want 1", result.Inserted)
	}
	if len(kms.inserted) != 0 {
		t.Error("dry-run must not write to storage")
	}
}

func TestMigrate_CAStorageError_ReturnsError(t *testing.T) {
	caStore := &mockCACertStorage{listErr: errors.New("db failure")}
	kms := newMockKMSStorage()

	_, err := Migrate(context.Background(), silentLogger(), caStore, kms, false)
	if err == nil {
		t.Fatal("expected error from CA storage failure, got nil")
	}
}
