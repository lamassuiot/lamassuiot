package assemblers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	lservices "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
)

type migrationTestLister struct {
	tenants []models.Tenant
}

func (lister migrationTestLister) ListNonDeletedTenants(context.Context) ([]models.Tenant, error) {
	return lister.tenants, nil
}

// SelectAll recorre las filas del tenant del contexto, como el querier de
// PostgreSQL bajo WithTenantTransaction.
func (repo *memoryKMSKeys) SelectAll(ctx context.Context, req storage.StorageListRequest[models.Key]) (string, error) {
	prefix, err := memoryKMSKeyID(ctx, "")
	if err != nil {
		return "", err
	}
	repo.mu.Lock()
	var keys []models.Key
	for id, key := range repo.keys {
		if len(id) > len(prefix) && id[:len(prefix)] == prefix {
			keys = append(keys, key)
		}
	}
	repo.mu.Unlock()
	for _, key := range keys {
		req.ApplyFunc(key)
	}
	return "", nil
}

type migrationFixture struct {
	t       *testing.T
	dir     string
	repo    *memoryKMSKeys
	globals []globalFilesystemEngine
	tenants []models.Tenant
}

func newMigrationFixture(t *testing.T, tenantIDs ...string) *migrationFixture {
	t.Helper()
	dir := t.TempDir()
	engines, err := createCryptoEngines(logrus.New().WithField("test", "migration"), globalFilesystemKMSConfig(dir))
	if err != nil {
		t.Fatalf("could not create crypto engines: %s", err)
	}
	fixture := &migrationFixture{
		t:    t,
		dir:  dir,
		repo: newMemoryKMSKeys(),
		globals: []globalFilesystemEngine{{
			engineID:         "filesystem-1",
			storageDirectory: dir,
			engine:           engines["filesystem-1"],
		}},
	}
	for _, tenantID := range tenantIDs {
		fixture.tenants = append(fixture.tenants, models.Tenant{ID: tenantID, OrganizationID: "organization", Status: models.TenantActive})
	}
	return fixture
}

func (fixture *migrationFixture) engine() *lservices.Engine {
	return fixture.globals[0].engine
}

// flatKey escribe una clave en la raíz plana, como antes de T4.2.
func (fixture *migrationFixture) flatKey() (*ecdsa.PrivateKey, string) {
	fixture.t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fixture.t.Fatalf("could not generate key: %s", err)
	}
	keyID, _, err := fixture.engine().Service.ImportECDSAPrivateKey(key)
	if err != nil {
		fixture.t.Fatalf("could not write flat key: %s", err)
	}
	return key, keyID
}

func (fixture *migrationFixture) row(tenantID, keyID string, key *ecdsa.PrivateKey) {
	fixture.t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		fixture.t.Fatalf("could not encode public key: %s", err)
	}
	encoded := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if _, err := fixture.repo.Insert(kmsEnginesTestContext(tenantID), &models.Key{KeyID: keyID, EngineID: "filesystem-1", TenantID: tenantID, PublicKey: encoded}); err != nil {
		fixture.t.Fatalf("could not insert row: %s", err)
	}
}

func (fixture *migrationFixture) migrate() (tenantKeyMigrationResult, error) {
	lister := func() (storage.NonDeletedTenantLister, error) {
		return migrationTestLister{tenants: fixture.tenants}, nil
	}
	return migrateGlobalFilesystemKeysToTenants(context.Background(), logrus.New().WithField("test", "migration"), fixture.globals, lister, fixture.repo)
}

func (fixture *migrationFixture) exists(parts ...string) bool {
	_, err := os.Lstat(filepath.Join(append([]string{fixture.dir}, parts...)...))
	return err == nil
}

func (fixture *migrationFixture) tenantSigner(tenantID, keyID string) error {
	instance, err := fixture.engine().DeriveForTenant(tenantID)
	if err != nil {
		return err
	}
	_, err = instance.GetPrivateKeyByID(keyID)
	return err
}

func TestTenantKeyMigrationMovesKeysAndListsOrphans(t *testing.T) {
	tenantA, tenantB := "tenant-a", "tenant-b"
	fixture := newMigrationFixture(t, tenantA, tenantB)
	keyA, idA := fixture.flatKey()
	keyB, idB := fixture.flatKey()
	shared, idShared := fixture.flatKey()
	_, idOrphan := fixture.flatKey()
	fixture.row(tenantA, idA, keyA)
	fixture.row(tenantB, idB, keyB)
	fixture.row(tenantA, idShared, shared)
	fixture.row(tenantB, idShared, shared)

	result, err := fixture.migrate()
	if err != nil {
		t.Fatalf("unexpected migration error: %s", err)
	}
	if result != (tenantKeyMigrationResult{Moved: 4, Orphans: 1}) {
		t.Fatalf("unexpected counts: %+v", result)
	}
	for _, check := range []struct{ tenant, keyID string }{{tenantA, idA}, {tenantB, idB}, {tenantA, idShared}, {tenantB, idShared}} {
		if err := fixture.tenantSigner(check.tenant, check.keyID); err != nil {
			t.Fatalf("tenant %s cannot read key %s after migrating: %s", check.tenant, check.keyID, err)
		}
	}
	if fixture.exists(idA) || fixture.exists(idB) || fixture.exists(idShared) {
		t.Fatal("migrated originals must be removed from the flat root")
	}
	if !fixture.exists(idOrphan) || fixture.exists("tenants", tenantA, idOrphan) || fixture.exists("tenants", tenantB, idOrphan) {
		t.Fatal("an orphan must stay in the flat root and not be assigned to any tenant")
	}

	result, err = fixture.migrate()
	if err != nil {
		t.Fatalf("unexpected error on the second run: %s", err)
	}
	if result != (tenantKeyMigrationResult{Orphans: 1}) {
		t.Fatalf("a second run must change nothing (only the orphan is listed again), got %+v", result)
	}
}

func TestTenantKeyMigrationKeepsOriginalWhenPublicKeyDoesNotMatch(t *testing.T) {
	fixture := newMigrationFixture(t, "tenant-a")
	_, keyID := fixture.flatKey()
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate key: %s", err)
	}
	fixture.row("tenant-a", keyID, other)

	result, err := fixture.migrate()
	if err == nil || result.Errors != 1 {
		t.Fatalf("expected a verification error, got result=%+v err=%v", result, err)
	}
	if !fixture.exists(keyID) {
		t.Fatal("the original must stay when verification fails")
	}
	if fixture.exists("tenants", "tenant-a", keyID) {
		t.Fatal("the unverified copy must be removed")
	}
}

func TestTenantKeyMigrationFinishesAnInterruptedRun(t *testing.T) {
	fixture := newMigrationFixture(t, "tenant-a")
	key, keyID := fixture.flatKey()
	fixture.row("tenant-a", keyID, key)
	// Ejecución interrumpida: el enlace está hecho y el original sin borrar.
	if _, err := fixture.engine().DeriveForTenant("tenant-a"); err != nil {
		t.Fatalf("could not create tenant root: %s", err)
	}
	if err := os.Link(filepath.Join(fixture.dir, keyID), filepath.Join(fixture.dir, "tenants", "tenant-a", keyID)); err != nil {
		t.Fatalf("could not simulate the interrupted run: %s", err)
	}

	result, err := fixture.migrate()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if result != (tenantKeyMigrationResult{AlreadyMigrated: 1}) {
		t.Fatalf("unexpected counts: %+v", result)
	}
	if fixture.exists(keyID) {
		t.Fatal("the original must be removed once the existing copy is verified")
	}
	if err := fixture.tenantSigner("tenant-a", keyID); err != nil {
		t.Fatalf("tenant cannot read its key: %s", err)
	}
}

func TestTenantKeyMigrationKeepsOriginalsWhileATenantIsSuspended(t *testing.T) {
	fixture := newMigrationFixture(t, "tenant-a")
	fixture.tenants = append(fixture.tenants, models.Tenant{ID: "tenant-s", OrganizationID: "organization", Status: models.TenantSuspended})
	key, keyID := fixture.flatKey()
	fixture.row("tenant-a", keyID, key)
	_, unknownID := fixture.flatKey()

	result, err := fixture.migrate()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if result != (tenantKeyMigrationResult{Moved: 1, Pending: 2}) {
		t.Fatalf("unexpected counts: %+v", result)
	}
	if !fixture.exists(keyID) || !fixture.exists(unknownID) {
		t.Fatal("originals must be kept while a tenant cannot be read")
	}
	if err := fixture.tenantSigner("tenant-a", keyID); err != nil {
		t.Fatalf("the readable tenant must already use its copy: %s", err)
	}
}

func TestTenantKeyMigrationSkipsWhenTheFlatRootIsEmpty(t *testing.T) {
	fixture := newMigrationFixture(t)
	lister := func() (storage.NonDeletedTenantLister, error) {
		t.Fatal("tenants must not be listed when there is nothing to migrate")
		return nil, nil
	}
	result, err := migrateGlobalFilesystemKeysToTenants(context.Background(), logrus.New().WithField("test", "migration"), fixture.globals, lister, fixture.repo)
	if err != nil || result != (tenantKeyMigrationResult{}) {
		t.Fatalf("expected an empty run, got result=%+v err=%v", result, err)
	}
}
