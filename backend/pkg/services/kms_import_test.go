package services

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/go-playground/validator/v10"
	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/engines/crypto/software/v3"
	"github.com/sirupsen/logrus"
)

const pgDuplicateKeyError = `ERROR: duplicate key value violates unique constraint "keys_pkey" (SQLSTATE 23505)`

// importTestEngine guarda el material en memoria. Con overwrite se comporta
// como Vault (Put reescribe); sin él, como filesystem (O_EXCL).
type importTestEngine struct {
	cryptoengines.CryptoEngine
	overwrite bool
	mu        sync.Mutex
	keys      map[string]crypto.Signer
	writes    int
}

func newImportTestEngine(overwrite bool) *importTestEngine {
	return &importTestEngine{overwrite: overwrite, keys: map[string]crypto.Signer{}}
}

func (engine *importTestEngine) GetEngineConfig() models.CryptoEngineInfo {
	return models.CryptoEngineInfo{SupportedKeyTypes: []models.SupportedKeyTypeInfo{
		{Type: models.KeyType(x509.ECDSA), Sizes: []int{256}},
		{Type: models.KeyType(x509.RSA), Sizes: []int{2048}},
	}}
}

func (engine *importTestEngine) GetPrivateKeyByID(keyID string) (crypto.Signer, error) {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	signer, ok := engine.keys[keyID]
	if !ok {
		return nil, errors.New("open " + keyID + ": no such file or directory")
	}
	return signer, nil
}

func (engine *importTestEngine) store(signer crypto.Signer) (string, crypto.Signer, error) {
	keyID, err := software.NewSoftwareCryptoEngine(logrus.NewEntry(logrus.New())).EncodePKIXPublicKeyDigest(signer.Public())
	if err != nil {
		return "", nil, err
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if _, exists := engine.keys[keyID]; exists && !engine.overwrite {
		return "", nil, errors.New("openat " + keyID + ": file exists")
	}
	engine.keys[keyID] = signer
	engine.writes++
	return keyID, signer, nil
}

func (engine *importTestEngine) ImportECDSAPrivateKey(key *ecdsa.PrivateKey) (string, crypto.Signer, error) {
	return engine.store(key)
}

func (engine *importTestEngine) ImportRSAPrivateKey(key *rsa.PrivateKey) (string, crypto.Signer, error) {
	return engine.store(key)
}

func (engine *importTestEngine) DeleteKey(keyID string) error {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	delete(engine.keys, keyID)
	return nil
}

func (engine *importTestEngine) has(keyID string) (crypto.Signer, bool) {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	signer, ok := engine.keys[keyID]
	return signer, ok
}

// importTestKeys es kms_keys con PK (tenant_id, key_id).
type importTestKeys struct {
	storage.KMSKeysRepo
	rows      map[string]models.Key
	insertErr error
	// racingInsert simula que otra petición del mismo tenant inserta la fila
	// justo antes que esta.
	racingInsert bool
}

func (repo *importTestKeys) id(ctx context.Context, keyID string) string {
	tenantContext, _ := core.RequireTenantContext(ctx)
	return tenantContext.TenantID + "/" + keyID
}

func (repo *importTestKeys) SelectExistsByKeyID(ctx context.Context, keyID string) (bool, *models.Key, error) {
	key, ok := repo.rows[repo.id(ctx, keyID)]
	if !ok {
		return false, nil, nil
	}
	return true, &key, nil
}

func (repo *importTestKeys) Insert(ctx context.Context, key *models.Key) (*models.Key, error) {
	if repo.racingInsert {
		repo.rows[repo.id(ctx, key.KeyID)] = *key
		return nil, errors.New(pgDuplicateKeyError)
	}
	if repo.insertErr != nil {
		return nil, repo.insertErr
	}
	if _, exists := repo.rows[repo.id(ctx, key.KeyID)]; exists {
		return nil, errors.New(pgDuplicateKeyError)
	}
	repo.rows[repo.id(ctx, key.KeyID)] = *key
	return key, nil
}

func newImportTestService(engine *importTestEngine, repo *importTestKeys) *KMSServiceBackend {
	kmsValidator = validator.New()
	var cryptoEngine cryptoengines.CryptoEngine = engine
	if repo.rows == nil {
		repo.rows = map[string]models.Key{}
	}
	return &KMSServiceBackend{
		cryptoEngines:         map[string]*cryptoengines.CryptoEngine{"engine": &cryptoEngine},
		engineTenants:         map[string]string{},
		defaultCryptoEngineID: "engine",
		kmsStorage:            repo,
		logger:                logrus.New().WithField("test", "kms-import"),
	}
}

func newImportTestKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate key: %s", err)
	}
	keyID, err := software.NewSoftwareCryptoEngine(logrus.NewEntry(logrus.New())).EncodePKIXPublicKeyDigest(key.Public())
	if err != nil {
		t.Fatalf("could not compute key ID: %s", err)
	}
	return key, keyID
}

func assertNoStorageDetails(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	for _, leak := range []string{"keys_pkey", "duplicate key", "SQLSTATE", "file exists"} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("error leaks %q: %s", leak, err)
		}
	}
}

func TestImportKeyRemovesWrittenMaterialWhenInsertFails(t *testing.T) {
	engine := newImportTestEngine(false)
	repo := &importTestKeys{insertErr: errors.New(`ERROR: could not serialize access (SQLSTATE 40001)`)}
	svc := newImportTestService(engine, repo)
	key, keyID := newImportTestKey(t)

	_, err := svc.ImportKey(testKMSValidTenantContext("tenant-a"), services.ImportKeyInput{PrivateKey: key})
	if !errors.Is(err, errs.ErrKeyImportFailed) {
		t.Fatalf("expected the generic import error, got %v", err)
	}
	assertNoStorageDetails(t, err)
	if _, ok := engine.has(keyID); ok {
		t.Fatal("the material written by the failed import must be removed")
	}
}

func TestImportKeyRejectsDuplicateInTheSameTenant(t *testing.T) {
	for _, overwrite := range []bool{false, true} {
		name := "exclusive engine"
		if overwrite {
			name = "overwriting engine"
		}
		t.Run(name, func(t *testing.T) {
			engine := newImportTestEngine(overwrite)
			svc := newImportTestService(engine, &importTestKeys{})
			key, keyID := newImportTestKey(t)
			ctx := testKMSValidTenantContext("tenant-a")

			if _, err := svc.ImportKey(ctx, services.ImportKeyInput{PrivateKey: key}); err != nil {
				t.Fatalf("first import: %s", err)
			}
			original, _ := engine.has(keyID)

			_, err := svc.ImportKey(ctx, services.ImportKeyInput{PrivateKey: key})
			if !errors.Is(err, errs.ErrKeyAlreadyExists) {
				t.Fatalf("expected ErrKeyAlreadyExists, got %v", err)
			}
			assertNoStorageDetails(t, err)
			current, ok := engine.has(keyID)
			if !ok || current != original || engine.writes != 1 {
				t.Fatalf("the original material must stay intact (present=%v, writes=%d)", ok, engine.writes)
			}
		})
	}
}

func TestImportKeyAdoptsOrphanOfTheSameTenant(t *testing.T) {
	engine := newImportTestEngine(false)
	repo := &importTestKeys{}
	svc := newImportTestService(engine, repo)
	key, keyID := newImportTestKey(t)
	if _, _, err := engine.store(key); err != nil {
		t.Fatalf("could not seed orphan material: %s", err)
	}
	engine.writes = 0

	imported, err := svc.ImportKey(testKMSValidTenantContext("tenant-a"), services.ImportKeyInput{PrivateKey: key, Name: "orphan"})
	if err != nil {
		t.Fatalf("expected the orphan to be adopted, got %v", err)
	}
	if imported.KeyID != keyID || imported.TenantID != "tenant-a" {
		t.Fatalf("unexpected adopted key: %+v", imported)
	}
	if engine.writes != 0 {
		t.Fatalf("adopting an orphan must not rewrite it, got %d writes", engine.writes)
	}
}

func TestImportKeyNeverRemovesPreviousMaterial(t *testing.T) {
	engine := newImportTestEngine(false)
	repo := &importTestKeys{insertErr: errors.New("connection reset")}
	svc := newImportTestService(engine, repo)
	key, keyID := newImportTestKey(t)
	if _, _, err := engine.store(key); err != nil {
		t.Fatalf("could not seed material: %s", err)
	}

	if _, err := svc.ImportKey(testKMSValidTenantContext("tenant-a"), services.ImportKeyInput{PrivateKey: key}); !errors.Is(err, errs.ErrKeyImportFailed) {
		t.Fatalf("expected the generic import error, got %v", err)
	}
	if _, ok := engine.has(keyID); !ok {
		t.Fatal("material that existed before the call must never be removed")
	}
}

func TestImportKeyLosingARaceKeepsTheWinnerMaterial(t *testing.T) {
	engine := newImportTestEngine(true)
	repo := &importTestKeys{racingInsert: true}
	svc := newImportTestService(engine, repo)
	key, keyID := newImportTestKey(t)

	_, err := svc.ImportKey(testKMSValidTenantContext("tenant-a"), services.ImportKeyInput{PrivateKey: key})
	if !errors.Is(err, errs.ErrKeyAlreadyExists) {
		t.Fatalf("expected ErrKeyAlreadyExists, got %v", err)
	}
	assertNoStorageDetails(t, err)
	if _, ok := engine.has(keyID); !ok {
		t.Fatal("the material of the request that won the race must stay")
	}
}
