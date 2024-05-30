package keystorager

import (
	"errors"
	"os"
	"testing"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	keyvaultkv2_test "github.com/lamassuiot/lamassuiot/v2/pkg/test/subsystems/cryptoengines/keyvaultkv2"
)

func setupVault(t *testing.T) (func(), *VaultKV2Engine) {
	// Create a new instance of GoCryptoEngine
	log := helpers.SetupLogger(config.Info, "CA TestCase", "Engine")

	teardown, vaultConfig, _, err := keyvaultkv2_test.RunHashicorpVaultDocker()
	if err != nil {
		t.Fatalf("Could not launch Hashicorp Vault: %s", err)
	}

	cfgVault := config.HashicorpVaultCryptoEngineConfig{
		HashicorpVaultSDK: *vaultConfig,
		ID:                "dockertest-hcpvault-kvv2",
		Metadata:          make(map[string]interface{}),
	}

	engine, err := NewVaultKV2Engine(log, cfgVault)
	if err != nil {
		log.Warnf("Skipping vault engine with id %s: %s", cfgVault.ID, err)
	}

	return func() {
		teardown()
	}, engine.(*VaultKV2Engine)
}

func TestStoreValue(t *testing.T) {
	teardown, engine := setupVault(t)
	defer teardown()

	keyID := "test-key"

	t.Run("StoreValue", func(t *testing.T) {
		str := "value-storagefunc"
		err := engine.Create(keyID, []byte(str))
		if err != nil {
			t.Fatalf("Failed to create RSA value: %s", err)
		}

		_, err = engine.Get(keyID)

		if err != nil {
			t.Errorf("Unexpected error while accesing to the vault value created in the previous step: %s", err)
		}
	})
}

func TestDeleteVaultValue(t *testing.T) {
	teardown, engine := setupVault(t)
	defer teardown()

	keyID := "test-key"

	// Test case: Delete existing value
	t.Run("DeleteExistingValue", func(t *testing.T) {
		err := engine.Create(keyID, []byte("testing-valueStorage"))
		if err != nil {
			t.Fatalf("Got an error while creating the value: %s", err)
		}
		err = engine.Delete(keyID)
		if err != nil {
			t.Fatalf("Failed to delete existing value: %s", err)
		}
		_, err = engine.Get(keyID)

		if err != nil {
			t.Logf("Expected error while accesing to vault to find the value, got: %s", err)
		}
	})

	// Test case: Delete non-existent value
	t.Run("DeleteNonExistentValue", func(t *testing.T) {
		nonExistentValueID := "non-existent-value"
		err := engine.Delete(nonExistentValueID)
		if err != nil {
			t.Logf("Expected error while accesing to vault to find the value that does not exist, got: %s", err)
		}
	})
}

func TestGetVaultValueByID(t *testing.T) {
	teardown, engine := setupVault(t)
	defer teardown()

	keyID := "test-key"

	err := engine.Create(keyID, []byte("value-storage"))

	// Test case: Get value by ID
	t.Run("GetValueByID", func(t *testing.T) {
		_, err = engine.Get(keyID)
		if err != nil {
			t.Errorf("Unexpected error whicle accessing to the value with the ID '%s'", keyID) //Aqui como no existe el objeto signer, se definido el errorf aqui, en el caso de que no lea bien la calve privada.
		}
		t.Logf("The value has loaded with the following ID '%s'", keyID)
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
