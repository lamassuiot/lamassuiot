package filesystem

import (
	"os"
	"testing"

	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/cryptoengines/legacy"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
)

func setup(t *testing.T) (string, *FilesystemCryptoEngine) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	// Create a new instance of GoCryptoEngine
	log := helpers.SetupLogger(cconfig.Info, "CA TestCase", "Golang Engine")
	ceconfig := cconfig.CryptoEngineConfigAdapter[FilesystemEngineConfig]{
		ID:       "test-engine",
		Metadata: map[string]any{},
		Type:     cconfig.FilesystemProvider,
		Config:   FilesystemEngineConfig{StorageDirectory: tempDir},
	}

	engine, _ := NewFilesystemPEMEngine(log, ceconfig)

	return tempDir, engine.(*FilesystemCryptoEngine)
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

	// The same engine, through the Backend contract (legacy adapter).
	for _, bt := range cryptoengines.SharedBackendTests() {
		table = append(table, struct {
			name     string
			function func(t *testing.T, engine cryptoengines.CryptoEngine)
		}{"Backend/" + bt.Name, func(t *testing.T, engine cryptoengines.CryptoEngine) { bt.Fn(t, legacy.Wrap(engine)) }})
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, engine := setup(t)
			defer teardown(tmpDir)

			tt.function(t, engine)
		})
	}

}
