package cryptoengines

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	keystorager "github.com/lamassuiot/lamassuiot/v2/pkg/cryptoengines/key_storager"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
)

func setup(t *testing.T) (string, *GoCryptoEngine) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	// Create a new instance of GoCryptoEngine
	log := helpers.SetupLogger(config.Info, "CA TestCase", "Golang Engine")

	keyStorage := keystorager.NewFilesystemKeyStorage(log, config.GolangFilesystemEngineConfig{StorageDirectory: tempDir})
	engine := NewGolangEngine(log, keyStorage, map[string]any{})

	return tempDir, engine.(*GoCryptoEngine)
}

func teardown(tempDir string) {
	// Remove the temporary directory
	os.RemoveAll(tempDir)
}

func TestGetPrivateKeyByID(t *testing.T) {
	tempDir, engine := setup(t)
	defer teardown(tempDir)

	// Create a test private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test private key: %s", err)
	}

	// Encode the private key to PEM format
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	privateKeyPEMBytes := pem.EncodeToMemory(privateKeyPEM)

	// Write the private key to a file in the temporary directory
	keyID := "test-key"
	keyFilePath := fmt.Sprintf("%s/%s", tempDir, keyID)
	err = os.WriteFile(keyFilePath, privateKeyPEMBytes, 0644)
	if err != nil {
		t.Fatalf("failed to write test private key to file: %s", err)
	}

	// Test case: Get private key by ID
	t.Run("GetPrivateKeyByID", func(t *testing.T) {
		signer, err := engine.GetPrivateKeyByID(keyID)
		if err != nil {
			t.Fatalf("failed to get private key by ID: %s", err)
		}

		// Check the type of the returned signer
		switch signer.(type) {
		case *rsa.PrivateKey:
			// Private key is of type RSA
			t.Logf("Private key with ID '%s' is of type RSA", keyID)
		case *ecdsa.PrivateKey:
			// Private key is of type ECDSA
			t.Logf("Private key with ID '%s' is of type ECDSA", keyID)
		default:
			t.Errorf("unexpected private key type for ID '%s'", keyID)
		}
	})

	// Test case: Get private key by non-existent ID
	t.Run("GetPrivateKeyByNonExistentID", func(t *testing.T) {
		nonExistentKeyID := "non-existent-key"
		_, err := engine.GetPrivateKeyByID(nonExistentKeyID)
		if !errors.Is(err, os.ErrNotExist) {
			t.Errorf("expected error os.ErrNotExist, got: %s", err)
		}
	})
}

func TestCreateRSAPrivateKey(t *testing.T) {
	tempDir, engine := setup(t)
	defer teardown(tempDir)

	testCreateRSAPrivateKey(t, engine)
}

func TestCreateECDSAPrivateKey(t *testing.T) {
	tempDir, engine := setup(t)
	defer teardown(tempDir)

	testCreateECDSAPrivateKey(t, engine)
}

func TestDeleteKey(t *testing.T) {
	tempDir, engine := setup(t)
	defer teardown(tempDir)

	keyID := "test-key"

	// Create a test private key file
	keyFilePath := fmt.Sprintf("%s/%s", tempDir, keyID)
	err := os.WriteFile(keyFilePath, []byte("test private key"), 0644)
	if err != nil {
		t.Fatalf("failed to write test private key to file: %s", err)
	}

	// Test case: Delete existing key
	t.Run("DeleteExistingKey", func(t *testing.T) {
		err := engine.DeleteKey(keyID)
		if err != nil {
			t.Fatalf("failed to delete existing key: %s", err)
		}

		// Check if the key file is deleted
		_, err = os.Stat(keyFilePath)
		if !errors.Is(err, os.ErrNotExist) {
			t.Errorf("expected key file to be deleted, got: %s", err)
		}
	})

	// Test case: Delete non-existent key
	t.Run("DeleteNonExistentKey", func(t *testing.T) {
		nonExistentKeyID := "non-existent-key"
		err := engine.DeleteKey(nonExistentKeyID)
		if !errors.Is(err, os.ErrNotExist) {
			t.Errorf("expected error os.ErrNotExist, got: %s", err)
		}
	})
}
func TestImportRSAPrivateKey(t *testing.T) {
	tempDir, engine := setup(t)
	defer teardown(tempDir)

	keyID := "test-key"

	t.Run("ImportRSAPrivateKey", func(t *testing.T) {
		// Generate a test RSA private key
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate test private key: %s", err)
		}

		// Import the RSA private key
		signer, err := engine.ImportRSAPrivateKey(privateKey, keyID)
		if err != nil {
			t.Fatalf("failed to import RSA private key: %s", err)
		}

		// Check the type of the returned signer
		switch signer.(type) {
		case *rsa.PrivateKey:
			// Private key is of type RSA
			t.Logf("Private key with ID '%s' is of type RSA", keyID)
		default:
			t.Errorf("unexpected private key type for ID '%s'", keyID)
		}

		// Verify that the private key is stored in the storage directory
		keyFilePath := fmt.Sprintf("%s/%s", tempDir, keyID)
		_, err = os.Stat(keyFilePath)
		if err != nil {
			t.Errorf("failed to find stored private key: %s", err)
		}
	})
}

func TestImportECDSAPrivateKey(t *testing.T) {
	tempDir, engine := setup(t)
	defer teardown(tempDir)

	keyID := "test-key"

	t.Run("ImportECDSAPrivateKey", func(t *testing.T) {
		// Generate a test ECDSA private key
		curve := elliptic.P256()
		privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate test private key: %s", err)
		}

		// Import the ECDSA private key
		signer, err := engine.ImportECDSAPrivateKey(privateKey, keyID)
		if err != nil {
			t.Fatalf("failed to import ECDSA private key: %s", err)
		}

		// Check the type of the returned signer
		switch signer.(type) {
		case *ecdsa.PrivateKey:
			// Private key is of type ECDSA
			t.Logf("Private key with ID '%s' is of type ECDSA", keyID)
		default:
			t.Errorf("unexpected private key type for ID '%s'", keyID)
		}

		// Verify that the private key is stored in the storage directory
		keyFilePath := fmt.Sprintf("%s/%s", tempDir, keyID)
		_, err = os.Stat(keyFilePath)
		if err != nil {
			t.Errorf("failed to find stored private key: %s", err)
		}
	})
}
