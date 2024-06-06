package keystorager

import (
	"errors"
	"os"
	"testing"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
)

func setupFileSystem(t *testing.T) (string, *FilesystemKeyStorage) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	// Create a new instance of GoCryptoEngine
	log := helpers.SetupLogger(config.Info, "CA TestCase", "Golang Engine")

	fileCfg := config.GolangFilesystemEngineConfig{
		ID:               "testing-value-storage",
		StorageDirectory: "testing",
	}
	keyStorage := NewFilesystemKeyStorage(log, fileCfg)

	return tempDir, keyStorage.(*FilesystemKeyStorage)
}

func TestCreateFileSystemValue(t *testing.T) {
	_, engine := setupFileSystem(t)

	keyID := "test-key"
	t.Run("CreateValue", func(t *testing.T) {
		str := "value-storagefunc"
		err := engine.Create(keyID, []byte(str))
		if err != nil {
			t.Fatalf("Failed to create the value in the file system: %s", err)
		}

		_, err = engine.Get(keyID)

		if err != nil {
			t.Errorf("Unexpected error while accesing to the file system value created in the previous step: %s", err)
		}
	})
}

func TestDeleteFileSystemValue(t *testing.T) {
	_, engine := setupFileSystem(t)

	keyID := "test-key"

	// Test case: Delete existing value
	t.Run("DeleteExistingValue", func(t *testing.T) {
		err := engine.Create(keyID, []byte("testing-valueStorage"))
		if err != nil {
			t.Fatalf("Got an error while creating the value in the the file system: %s", err)
		}
		err = engine.Delete(keyID)
		if err != nil {
			t.Errorf("Failed to delete existing value in the the file system: %s", err)
		}
		_, err = engine.Get(keyID)

		if err != nil {
			t.Logf("Expected error while accesing to the file system to find the value, got: %s", err)
		}
	})

	// Test case: Delete non-existent value
	t.Run("DeleteNonExistentValue", func(t *testing.T) {
		nonExistentValueID := "non-existent-value"
		err := engine.Delete(nonExistentValueID)
		if err != nil {
			t.Logf("Expected error while accesing to the file system to find the value that does not exist, got: %s", err)
		}
	})
}

func TestGetFileSystemValueByID(t *testing.T) {
	_, engine := setupFileSystem(t)

	keyID := "test-key"

	err := engine.Create(keyID, []byte("value-storage"))

	// Test case: Get the value by ID
	t.Run("GetValueByID", func(t *testing.T) {
		_, err = engine.Get(keyID)
		if err != nil {
			t.Errorf("Unexpected error while accessing to the file system the value with the ID '%s'", keyID) //Aqui como no existe el objeto signer, se definido el errorf aqui, en el caso de que no lea bien la calve privada.
		}
		t.Logf("The value has loaded from the file system with the following ID '%s'", keyID)
	})

	// Test case: Get value by non-existent ID
	t.Run("GetValueByNonExistentID", func(t *testing.T) {
		nonExistentValueID := "non-existent-value"
		_, err := engine.Get(nonExistentValueID)
		if !errors.Is(err, os.ErrNotExist) {
			t.Logf("Expected error os.ErrNotExist, got: %s", err)
		}
	})
}
