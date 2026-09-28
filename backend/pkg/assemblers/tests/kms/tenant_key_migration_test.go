package kms

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers"
	testassemblers "github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers/tests"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	cebuilder "github.com/lamassuiot/lamassuiot/backend/v3/pkg/cryptoengines/builder"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/storage/builder"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

// TestKMSStartupMigratesFlatRootKeysToTenants (004 T4.6): el arranque de KMS
// mueve las claves de la raíz plana del engine filesystem global a
// tenants/<tenant>/ según las filas de kms_keys de cada tenant en PostgreSQL.
func TestKMSStartupMigratesFlatRootKeysToTenants(t *testing.T) {
	tenantA := "00000000-0000-0000-0000-00000000000a"
	tenantB := "00000000-0000-0000-0000-00000000000b"
	storageConfig, err := testassemblers.PreparePostgresForTest([]string{"kms"}, tenantA, tenantB)
	if err != nil {
		t.Fatalf("could not prepare PostgreSQL: %s", err)
	}
	t.Cleanup(storageConfig.AfterSuite)
	if err := storageConfig.BeforeEach(); err != nil {
		t.Fatalf("could not seed PostgreSQL: %s", err)
	}
	cryptoConfig := testassemblers.PrepareCryptoEnginesForTest([]testassemblers.CryptoEngine{testassemblers.GOLANG})
	t.Cleanup(cryptoConfig.AfterSuite)
	engineConfig := cryptoConfig.Config.CryptoEngines[0]
	dir := engineConfig.Config["storage_directory"].(string)

	logger := logrus.NewEntry(logrus.New())
	flatEngine, err := cebuilder.BuildCryptoEngine(logger, engineConfig)
	if err != nil {
		t.Fatalf("could not open the flat root: %s", err)
	}
	storageEngine, err := builder.BuildStorageEngine(logger, storageConfig.Config)
	if err != nil {
		t.Fatalf("could not build storage: %s", err)
	}
	kmsKeys, err := storageEngine.GetKMSStorage()
	if err != nil {
		t.Fatalf("could not get KMS storage: %s", err)
	}

	// Estado anterior a 004 T4.2: material en la raíz plana y filas por tenant.
	flatKey := func() (*ecdsa.PrivateKey, string) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("could not generate key: %s", err)
		}
		keyID, _, err := flatEngine.ImportECDSAPrivateKey(key)
		if err != nil {
			t.Fatalf("could not write flat key: %s", err)
		}
		return key, keyID
	}
	row := func(tenantID, keyID string, key *ecdsa.PrivateKey) {
		der, err := x509.MarshalPKIXPublicKey(key.Public())
		if err != nil {
			t.Fatalf("could not encode public key: %s", err)
		}
		_, err = kmsKeys.Insert(kmsTenantTestContext(tenantID), &models.Key{
			KeyID:         keyID,
			EngineID:      engineConfig.ID,
			TenantID:      tenantID,
			PKCS11URI:     "pkcs11:token-id=" + engineConfig.ID + ";id=" + keyID + ";type=private",
			Name:          "legacy-" + tenantID,
			Aliases:       []string{},
			HasPrivateKey: true,
			Algorithm:     "ECDSA",
			Size:          256,
			PublicKey:     base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
			Tags:          []string{},
			Metadata:      map[string]any{},
		})
		if err != nil {
			t.Fatalf("could not insert legacy row: %s", err)
		}
	}
	keyA, idA := flatKey()
	keyB, idB := flatKey()
	shared, idShared := flatKey()
	_, idOrphan := flatKey()
	row(tenantA, idA, keyA)
	row(tenantB, idB, keyB)
	row(tenantA, idShared, shared)
	row(tenantB, idShared, shared)

	kmsConfig := config.KMSConfig{
		Logs:               cconfig.Logging{Level: cconfig.Info},
		Server:             cconfig.HttpServer{LogLevel: cconfig.Info, Protocol: cconfig.HTTP},
		CryptoEngineConfig: cryptoConfig.Config,
		Storage:            storageConfig.Config,
		PublisherEventBus:  cconfig.EventBusEngine{Enabled: false},
	}
	assemble := func() services.KMSService {
		t.Helper()
		svc, err := assemblers.AssembleKMSService(kmsConfig)
		if err != nil {
			t.Fatalf("KMS startup failed: %s", err)
		}
		return *svc
	}
	exists := func(parts ...string) bool {
		_, err := os.Lstat(filepath.Join(append([]string{dir}, parts...)...))
		return err == nil
	}
	mustSign := func(svc services.KMSService, tenantID, keyID string, key *ecdsa.PrivateKey) {
		t.Helper()
		message := []byte("004 T4.6")
		signature, err := svc.SignMessage(kmsTenantTestContext(tenantID), services.SignMessageInput{
			Identifier:  keyID,
			Algorithm:   "ECDSA_SHA_256",
			Message:     message,
			MessageType: models.Raw,
		})
		if err != nil {
			t.Fatalf("tenant %s cannot sign with key %s: %s", tenantID, keyID, err)
		}
		digest := sha256.Sum256(message)
		if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], signature.Signature) {
			t.Fatalf("tenant %s signature with key %s does not verify", tenantID, keyID)
		}
	}
	checkMigrated := func() {
		t.Helper()
		for _, path := range [][]string{{"tenants", tenantA, idA}, {"tenants", tenantB, idB}, {"tenants", tenantA, idShared}, {"tenants", tenantB, idShared}} {
			if !exists(path...) {
				t.Fatalf("expected migrated key at %v", path)
			}
		}
		if exists(idA) || exists(idB) || exists(idShared) {
			t.Fatal("migrated originals must be removed from the flat root")
		}
		if !exists(idOrphan) || exists("tenants", tenantA, idOrphan) || exists("tenants", tenantB, idOrphan) {
			t.Fatal("the orphan must stay in the flat root without being assigned")
		}
	}

	svc := assemble()
	checkMigrated()
	mustSign(svc, tenantA, idA, keyA)
	mustSign(svc, tenantB, idB, keyB)
	mustSign(svc, tenantA, idShared, shared)
	mustSign(svc, tenantB, idShared, shared)

	// Segundo arranque: la migración es idempotente.
	svc = assemble()
	checkMigrated()
	mustSign(svc, tenantA, idA, keyA)
	mustSign(svc, tenantB, idShared, shared)

	// Una fila cuya clave pública no coincide con el material detiene el
	// arranque sin borrar el original.
	mismatched, idMismatched := flatKey()
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate key: %s", err)
	}
	row(tenantA, idMismatched, other)
	if _, err := assemblers.AssembleKMSService(kmsConfig); err == nil {
		t.Fatal("expected KMS startup to fail when the public key does not match")
	}
	if !exists(idMismatched) || exists("tenants", tenantA, idMismatched) {
		t.Fatal("a failed verification must keep the original and remove the unverified copy")
	}
	_ = mismatched
}
