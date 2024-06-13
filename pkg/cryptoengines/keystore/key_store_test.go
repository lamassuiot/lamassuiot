package keystore

import (
	"fmt"
	"testing"
)

type keystoreTestProvider struct {
	Setup func() (KeyStore, func(), error)
}

func getKeyStoreTestProvider() map[string]keystoreTestProvider {
	return map[string]keystoreTestProvider{
		"AWSSecretManager": setupAWSSecretManagerKeyProvider(),
		"Filesystem":       setupFilesystemKeyProvider(),
		"Vault":            setupVaultKeyProvider(),
		"S3":               setupS3KeyProvider(),
	}
}

var secretValue = "my super secret value"

func TestCreateKey(t *testing.T) {
	keyStoreProviders := getKeyStoreTestProvider()

	for keyStoreProviderName, keyStoreInitializer := range keyStoreProviders {
		keyStore, teardown, err := keyStoreInitializer.Setup()
		if err != nil {
			t.Fatalf("Failed to initialize the key store provider %s: %s", keyStoreProviderName, err)
		}

		defer teardown()

		t.Run(fmt.Sprintf("%s-StoreValue", keyStoreProviderName), func(t *testing.T) {
			keyID := "test-key"

			err := keyStore.Create(keyID, []byte(secretValue))
			if err != nil {
				t.Fatalf("Failed to store value: %s", err)
			}

			_, err = keyStore.Get(keyID)
			if err != nil {
				t.Errorf("Unexpected error: %s", err)
			}
		})
	}
}

func TestGetKey(t *testing.T) {
	keyStoreProviders := getKeyStoreTestProvider()

	for keyStoreProviderName, keyStoreInitializer := range keyStoreProviders {
		keyStore, teardown, err := keyStoreInitializer.Setup()
		if err != nil {
			t.Fatalf("Failed to initialize the key store provider %s: %s", keyStoreProviderName, err)
		}

		defer teardown()

		t.Run(fmt.Sprintf("%s-GetValueByID", keyStoreProviderName), func(t *testing.T) {
			keyID := "test-key"
			err := keyStore.Create(keyID, []byte(secretValue))
			if err != nil {
				t.Fatalf("Got unexpected error: %s", err)
			}

			_, err = keyStore.Get(keyID)
			if err != nil {
				t.Fatalf("Failed to get value with ID '%s': %s", keyID, err)
			}
		})

		// Test case: Get value by non-existent ID
		t.Run(fmt.Sprintf("%s-GetValueByNonExistentID", keyStoreProviderName), func(t *testing.T) {
			nonExistentValueID := "non-existent-value"
			_, err := keyStore.Get(nonExistentValueID)
			if err == nil {
				t.Error("Expected error, but it does not return any error")
			}
		})
	}
}

func TestDeleteKey(t *testing.T) {
	keyStoreProviders := getKeyStoreTestProvider()

	for keyStoreProviderName, keyStoreInitializer := range keyStoreProviders {
		keyStore, teardown, err := keyStoreInitializer.Setup()
		if err != nil {
			t.Fatalf("Failed to initialize the key store provider %s: %s", keyStoreProviderName, err)
		}

		defer teardown()

		// Test case: Delete existing value
		t.Run(fmt.Sprintf("%s-DeleteExistingValue", keyStoreProviderName), func(t *testing.T) {
			keyID := "test-key"
			err := keyStore.Create(keyID, []byte(secretValue))
			if err != nil {
				t.Fatalf("Got unexpected error: %s", err)
			}
			err = keyStore.Delete(keyID)
			if err != nil {
				t.Fatalf("Failed to delete value with ID '%s': %s", keyID, err)
			}
		})

		// Test case: Delete existing value
		t.Run(fmt.Sprintf("%s-DeleteExistingValue", keyStoreProviderName), func(t *testing.T) {
			nonExistentValueID := "non-existent-value"
			err := keyStore.Delete(nonExistentValueID)
			if err == nil {
				t.Logf("Expected an error, got none: %s", err)
			}
		})
	}
}
