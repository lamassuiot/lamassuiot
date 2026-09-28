package assemblers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	lservices "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	core "github.com/lamassuiot/lamassuiot/core/v3"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

// memoryKMSKeys guarda las filas de kms_keys por (tenant_id, key_id), como la
// PK de PostgreSQL desde 003 T13.
type memoryKMSKeys struct {
	storage.KMSKeysRepo
	mu   sync.Mutex
	keys map[string]models.Key
}

func newMemoryKMSKeys() *memoryKMSKeys {
	return &memoryKMSKeys{keys: map[string]models.Key{}}
}

func memoryKMSKeyID(ctx context.Context, keyID string) (string, error) {
	tenantContext, err := core.RequireTenantContext(ctx)
	if err != nil {
		return "", err
	}
	return tenantContext.TenantID + "/" + keyID, nil
}

func (repo *memoryKMSKeys) Insert(ctx context.Context, key *models.Key) (*models.Key, error) {
	id, err := memoryKMSKeyID(ctx, key.KeyID)
	if err != nil {
		return nil, err
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if _, exists := repo.keys[id]; exists {
		return nil, errors.New(`ERROR: duplicate key value violates unique constraint "keys_pkey" (SQLSTATE 23505)`)
	}
	repo.keys[id] = *key
	return key, nil
}

func (repo *memoryKMSKeys) SelectExistsByKeyID(ctx context.Context, keyID string) (bool, *models.Key, error) {
	id, err := memoryKMSKeyID(ctx, keyID)
	if err != nil {
		return false, nil, err
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	key, exists := repo.keys[id]
	if !exists {
		return false, nil, nil
	}
	return true, &key, nil
}

func (repo *memoryKMSKeys) SelectExistsByAlias(context.Context, string) (bool, *models.Key, error) {
	return false, nil, nil
}

func (repo *memoryKMSKeys) Delete(ctx context.Context, keyID string) error {
	id, err := memoryKMSKeyID(ctx, keyID)
	if err != nil {
		return err
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	delete(repo.keys, id)
	return nil
}

func kmsEnginesTestContext(tenantID string) context.Context {
	return core.WithTenantContext(context.Background(), core.TenantContext{
		OrganizationID: "organization",
		TenantID:       tenantID,
		ActorID:        "actor",
		ActorType:      "test",
		CorrelationID:  "correlation",
		Source:         "test",
		TenantStatus:   core.TenantActive,
		Validated:      true,
	})
}

func globalFilesystemKMSConfig(dir string) config.KMSConfig {
	return config.KMSConfig{
		CryptoEngineConfig: config.CryptoEngines{
			LogLevel:      cconfig.Info,
			DefaultEngine: "filesystem-1",
			CryptoEngines: []cconfig.CryptoEngineConfig{{
				ID:       "filesystem-1",
				Type:     cconfig.FilesystemProvider,
				Metadata: map[string]interface{}{},
				Config:   map[string]interface{}{"storage_directory": dir},
			}},
		},
	}
}

func newGlobalFilesystemKMS(t *testing.T, dir string, repo storage.KMSKeysRepo) services.KMSService {
	t.Helper()
	logger := logrus.New().WithField("test", "kms-engines")
	engines, err := createCryptoEngines(logger, globalFilesystemKMSConfig(dir))
	if err != nil {
		t.Fatalf("could not create crypto engines: %s", err)
	}
	svc, err := lservices.NewKMSService(lservices.KMSServiceBuilder{
		Logger:        logger,
		KMSStorage:    repo,
		CryptoEngines: engines,
	})
	if err != nil {
		t.Fatalf("could not create KMS service: %s", err)
	}
	return svc
}

func TestGlobalFilesystemEngineWritesUnderTenantRoots(t *testing.T) {
	dir := t.TempDir()
	svc := newGlobalFilesystemKMS(t, dir, newMemoryKMSKeys())
	tenantA := "00000000-0000-0000-0000-00000000000a"
	tenantB := "00000000-0000-0000-0000-00000000000b"

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate key: %s", err)
	}
	keyA, err := svc.ImportKey(kmsEnginesTestContext(tenantA), services.ImportKeyInput{PrivateKey: privateKey, Name: "a"})
	if err != nil {
		t.Fatalf("tenant A import: %s", err)
	}
	keyB, err := svc.ImportKey(kmsEnginesTestContext(tenantB), services.ImportKeyInput{PrivateKey: privateKey, Name: "b"})
	if err != nil {
		t.Fatalf("tenant B import: %s", err)
	}
	if keyA.KeyID != keyB.KeyID {
		t.Fatalf("expected the same key ID, got %s and %s", keyA.KeyID, keyB.KeyID)
	}

	created, err := svc.CreateKey(kmsEnginesTestContext(models.DefaultTenantID), services.CreateKeyInput{Algorithm: "ECDSA", Size: 256, Name: "default"})
	if err != nil {
		t.Fatalf("default tenant create: %s", err)
	}

	for _, path := range []string{
		filepath.Join(dir, "tenants", tenantA, keyA.KeyID),
		filepath.Join(dir, "tenants", tenantB, keyB.KeyID),
		filepath.Join(dir, "tenants", models.DefaultTenantID, created.KeyID),
	} {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("expected key material at %s: %v", path, err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("could not read the flat root: %s", err)
	}
	for _, entry := range entries {
		if entry.Name() != "tenants" {
			t.Fatalf("the flat root must not receive writes, found %s", entry.Name())
		}
	}
}

func TestDefaultEngineRejectsGlobalPKCS11(t *testing.T) {
	conf := config.KMSConfig{
		CryptoEngineConfig: config.CryptoEngines{
			DefaultEngine: "hsm",
			CryptoEngines: []cconfig.CryptoEngineConfig{{
				ID:     "hsm",
				Type:   cconfig.PKCS11Provider,
				Config: map[string]interface{}{},
			}},
		},
	}
	_, err := createCryptoEngines(logrus.New().WithField("test", "kms-engines"), conf)
	if err == nil || !strings.Contains(err.Error(), "PKCS#11") {
		t.Fatalf("expected a global PKCS#11 default engine to be rejected at startup, got %v", err)
	}
}
