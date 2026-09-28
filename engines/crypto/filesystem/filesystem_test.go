package filesystem

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"

	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
)

func setup(t *testing.T) (string, *FilesystemCryptoEngine) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	// Create a new instance of GoCryptoEngine
	log := helpers.SetupLogger(cconfig.Info, "CA TestCase", "Golang Engine")
	ceconfig := cconfig.CryptoEngineConfigAdapter[FilesystemEngineConfig]{
		ID:       "test-engine",
		Metadata: map[string]interface{}{},
		Type:     cconfig.FilesystemProvider,
		Config:   FilesystemEngineConfig{StorageDirectory: tempDir},
	}

	engine, _ := NewFilesystemPEMEngine(log, ceconfig)

	return tempDir, engine.(*FilesystemCryptoEngine)
}

func TestTenantScopedStorageRootRejectsOverwriteAndUnsafeKeyID(t *testing.T) {
	base := t.TempDir()
	logger := helpers.SetupLogger(cconfig.Info, "CA TestCase", "Filesystem Engine")
	conf := cconfig.CryptoEngineConfigAdapter[FilesystemEngineConfig]{
		ID:       "tenant-engine",
		TenantID: "tenant-a",
		Metadata: map[string]interface{}{},
		Type:     cconfig.FilesystemProvider,
		Config:   FilesystemEngineConfig{StorageDirectory: base},
	}
	cryptoEngine, err := NewFilesystemPEMEngine(logger, conf)
	if err != nil {
		t.Fatalf("could not create tenant-scoped engine: %s", err)
	}
	engine := cryptoEngine.(*FilesystemCryptoEngine)
	if engine.storageDirectory != filepath.Join(base, "tenants", "tenant-a") {
		t.Fatalf("unexpected tenant storage path: %s", engine.storageDirectory)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("could not generate test key: %s", err)
	}
	keyID, _, err := engine.ImportRSAPrivateKey(key)
	if err != nil {
		t.Fatalf("could not import key: %s", err)
	}
	if _, _, err := engine.ImportRSAPrivateKey(key); err == nil {
		t.Fatal("duplicate key import unexpectedly overwrote the existing key")
	}
	if _, err := engine.GetPrivateKeyByID("../escape"); err == nil {
		t.Fatal("unsafe key ID was accepted")
	}
	if _, err := os.Lstat(filepath.Join(base, "tenants", "tenant-a", keyID)); err != nil {
		t.Fatalf("key was not written under the tenant-scoped root: %s", err)
	}
}

func teardown(tempDir string) {
	// Remove the temporary directory
	os.RemoveAll(tempDir)
}

func TestVaultCryptoEngine(t *testing.T) {
	table := []struct {
		name     string
		function func(t *testing.T, engine cryptoengines.CryptoEngine)
	}{
		{"CreateECDSAPrivateKey", cryptoengines.SharedTestCreateECDSAPrivateKey},
		{"CreateRSAPrivateKey", cryptoengines.SharedTestCreateRSAPrivateKey},
		{"SignRSA_PSS", cryptoengines.SharedTestRSAPSSSignature},
		{"SignRSA_PKCS1v1_5", cryptoengines.SharedTestRSAPKCS1v15Signature},
		{"SignECDSA", cryptoengines.SharedTestECDSASignature},
		{"DeleteKey", cryptoengines.SharedTestDeleteKey},
		{"GetPrivateKeyByID", cryptoengines.SharedGetKey},
		{"GetPrivateKeyByIDNotFound", cryptoengines.SharedGetKeyNotFound},
		{"ListPrivateKeyIDs", cryptoengines.SharedListKeys},
		{"RenameKey", cryptoengines.SharedRenameKey},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, engine := setup(t)
			defer teardown(tmpDir)
			defer engine.Close()

			tt.function(t, engine)
		})
	}

}

func TestTenantRootConfinementAndPermissions(t *testing.T) {
	base := t.TempDir()
	logger := helpers.SetupLogger(cconfig.Info, "CA TestCase", "Filesystem Engine")

	newTenantEngine := func(tenantID string) *FilesystemCryptoEngine {
		conf := cconfig.CryptoEngineConfigAdapter[FilesystemEngineConfig]{
			ID:       "tenant-engine-" + tenantID,
			TenantID: tenantID,
			Metadata: map[string]interface{}{},
			Type:     cconfig.FilesystemProvider,
			Config:   FilesystemEngineConfig{StorageDirectory: base},
		}
		cryptoEngine, err := NewFilesystemPEMEngine(logger, conf)
		if err != nil {
			t.Fatalf("could not create tenant-scoped engine: %s", err)
		}
		return cryptoEngine.(*FilesystemCryptoEngine)
	}

	tenantA := newTenantEngine("tenant-a")
	defer tenantA.Close()
	tenantB := newTenantEngine("tenant-b")
	defer tenantB.Close()

	rootInfo, err := os.Stat(tenantA.storageDirectory)
	if err != nil {
		t.Fatalf("could not stat tenant storage root: %s", err)
	}
	if rootInfo.Mode().Perm() != 0700 {
		t.Fatalf("tenant storage root permissions = %04o, want 0700", rootInfo.Mode().Perm())
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("could not generate tenant B key: %s", err)
	}
	foreignKeyID, _, err := tenantB.ImportRSAPrivateKey(key)
	if err != nil {
		t.Fatalf("could not import tenant B key: %s", err)
	}

	linkPath := filepath.Join(tenantA.storageDirectory, "foreign-key")
	linkTarget := filepath.Join("..", "tenant-b", foreignKeyID)
	if err := os.Symlink(linkTarget, linkPath); err != nil {
		t.Skipf("symlinks are unavailable: %s", err)
	}

	if _, err := tenantA.GetPrivateKeyByID("foreign-key"); err == nil {
		t.Fatal("tenant A read a key through a symlink into tenant B")
	}
	if _, err := os.Stat(filepath.Join(tenantB.storageDirectory, foreignKeyID)); err != nil {
		t.Fatalf("tenant B key was affected by tenant A access: %s", err)
	}
}
