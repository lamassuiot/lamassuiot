package kms

import (
	"cloudflare/circl/sign/mldsa/mldsa44"
	"cloudflare/circl/sign/mldsa/mldsa65"
	"cloudflare/circl/sign/mldsa/mldsa87"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers/tests"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func StartKMSServiceTestServer(t *testing.T, withEventBus bool) (*tests.KMSTestServer, error) {
	builder := tests.TestServiceBuilder{}.WithDatabase("kms", "ca").WithVault()
	testServer, err := builder.Build(t)
	if err != nil {
		return nil, fmt.Errorf("could not create Device Manager test server: %s", err)
	}

	err = testServer.BeforeEach()
	if err != nil {
		t.Fatalf("could not run 'BeforeEach' cleanup func in test case: %s", err)
	}

	return testServer.KMS, nil
}

func TestCryptoEngines(t *testing.T) {
	kmsTest, err := StartKMSServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create KMS test server: %s", err)
	}

	var testcases = []struct {
		name        string
		resultCheck func(engines []*models.CryptoEngineProvider, err error) error
	}{
		{
			name: "OK/Got-2-Engines",
			resultCheck: func(engines []*models.CryptoEngineProvider, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error, but got one: %s", err)
				}

				if len(engines) != 2 {
					return fmt.Errorf("should've got two engines, but got %d", len(engines))
				}

				return nil
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {

			err = kmsTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' func in test case: %s", err)
			}

			err = tc.resultCheck(kmsTest.Service.GetCryptoEngineProvider(context.Background()))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}

		})
	}
}

func TestCreateKey(t *testing.T) {
	kmsTest, err := StartKMSServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create KMS test server: %s", err)
	}

	var testcases = []struct {
		name        string
		before      func(svc services.KMSService) error
		run         func(kmsSDK services.KMSService) (*models.Key, error)
		resultCheck func(createdKey *models.Key, err error) error
	}{
		{
			name:   "OK/KeyType-RSA-DefaultEngine",
			before: func(svc services.KMSService) error { return nil },
			run: func(kmsSDK services.KMSService) (*models.Key, error) {
				return kmsSDK.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "Test RSA Key",
					Algorithm: "RSA",
					Size:      2048,
				})
			},
			resultCheck: func(createdKey *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should've created KMS key without error, but got error: %s", err)
				}

				keyUriParts, err := parsePKCS11URI(createdKey.PKCS11URI)
				if err != nil {
					return fmt.Errorf("failed to parse created key ID as PKCS#11 URI: %s", err)
				}

				if createdKey == nil || createdKey.Name != "Test RSA Key" || createdKey.Algorithm != "RSA" || createdKey.Size != 2048 || !strings.HasPrefix(createdKey.PKCS11URI, "pkcs11:") || keyUriParts["token-id"] != "filesystem-1" {
					return fmt.Errorf("unexpected key result for RSA DefaultEngine: %+v", createdKey)
				}

				return nil
			},
		},
		{
			name:   "OK/KeyType-RSA-NonDefaultEngine",
			before: func(svc services.KMSService) error { return nil },
			run: func(kmsSDK services.KMSService) (*models.Key, error) {
				return kmsSDK.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "Test RSA Key Vault",
					Algorithm: "RSA",
					Size:      2048,
					EngineID:  "vault-1",
				})
			},
			resultCheck: func(createdKey *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should've created KMS key without error, but got error: %s", err)
				}

				keyUriParts, err := parsePKCS11URI(createdKey.PKCS11URI)
				if err != nil {
					return fmt.Errorf("failed to parse created key ID as PKCS#11 URI: %s", err)
				}

				if createdKey == nil || createdKey.Name != "Test RSA Key Vault" || createdKey.Algorithm != "RSA" || createdKey.Size != 2048 || !strings.HasPrefix(createdKey.PKCS11URI, "pkcs11:") || keyUriParts["token-id"] != "vault-1" {
					return fmt.Errorf("unexpected key result for RSA NonDefaultEngine: %+v", createdKey)
				}

				return nil
			},
		},
		{
			name:   "OK/KeyType-RSA",
			before: func(svc services.KMSService) error { return nil },
			run: func(kmsSDK services.KMSService) (*models.Key, error) {
				return kmsSDK.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "Test RSA Key",
					Algorithm: "RSA",
					Size:      2048,
					EngineID:  "filesystem-1",
				})
			},
			resultCheck: func(createdKey *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should've created KMS key without error, but got error: %s", err)
				}

				return nil
			},
		},
		{
			name:   "OK/KeyType-RSA-3072",
			before: func(svc services.KMSService) error { return nil },
			run: func(kmsSDK services.KMSService) (*models.Key, error) {
				return kmsSDK.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "Test RSA 3072 Key",
					Algorithm: "RSA",
					Size:      3072,
					EngineID:  "filesystem-1",
				})
			},
			resultCheck: func(createdKey *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should've created RSA 3072 key without error, but got error: %s", err)
				}
				if createdKey == nil || createdKey.Algorithm != "RSA" || createdKey.Size != 3072 {
					return fmt.Errorf("unexpected key result for RSA 3072: %+v", createdKey)
				}
				return nil
			},
		},
		{
			name:   "OK/KeyType-RSA-4096",
			before: func(svc services.KMSService) error { return nil },
			run: func(kmsSDK services.KMSService) (*models.Key, error) {
				return kmsSDK.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "Test RSA 4096 Key",
					Algorithm: "RSA",
					Size:      4096,
					EngineID:  "filesystem-1",
				})
			},
			resultCheck: func(createdKey *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should've created RSA 4096 key without error, but got error: %s", err)
				}
				if createdKey == nil || createdKey.Algorithm != "RSA" || createdKey.Size != 4096 {
					return fmt.Errorf("unexpected key result for RSA 4096: %+v", createdKey)
				}
				return nil
			},
		},
		{
			name:   "OK/KeyType-ECDSA-256",
			before: func(svc services.KMSService) error { return nil },
			run: func(kmsSDK services.KMSService) (*models.Key, error) {
				return kmsSDK.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "Test ECDSA 256 Key",
					Algorithm: "ECDSA",
					Size:      256,
					EngineID:  "filesystem-1",
				})
			},
			resultCheck: func(createdKey *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should've created ECDSA 256 key without error, but got error: %s", err)
				}
				if createdKey == nil || createdKey.Algorithm != "ECDSA" || createdKey.Size != 256 {
					return fmt.Errorf("unexpected key result for ECDSA 256: %+v", createdKey)
				}
				return nil
			},
		},
		{
			name:   "OK/KeyType-ECDSA-384",
			before: func(svc services.KMSService) error { return nil },
			run: func(kmsSDK services.KMSService) (*models.Key, error) {
				return kmsSDK.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "Test ECDSA 384 Key",
					Algorithm: "ECDSA",
					Size:      384,
					EngineID:  "filesystem-1",
				})
			},
			resultCheck: func(createdKey *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should've created ECDSA 384 key without error, but got error: %s", err)
				}
				if createdKey == nil || createdKey.Algorithm != "ECDSA" || createdKey.Size != 384 {
					return fmt.Errorf("unexpected key result for ECDSA 384: %+v", createdKey)
				}
				return nil
			},
		},
		{
			name:   "OK/KeyType-ECDSA-521",
			before: func(svc services.KMSService) error { return nil },
			run: func(kmsSDK services.KMSService) (*models.Key, error) {
				return kmsSDK.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "Test ECDSA 521 Key",
					Algorithm: "ECDSA",
					Size:      521,
					EngineID:  "filesystem-1",
				})
			},
			resultCheck: func(createdKey *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should've created ECDSA 521 key without error, but got error: %s", err)
				}
				if createdKey == nil || createdKey.Algorithm != "ECDSA" || createdKey.Size != 521 {
					return fmt.Errorf("unexpected key result for ECDSA 521: %+v", createdKey)
				}
				return nil
			},
		},
		{
			name:   "Error/MissingAlgorithm",
			before: func(svc services.KMSService) error { return nil },
			run: func(kmsSDK services.KMSService) (*models.Key, error) {
				return kmsSDK.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "No Algorithm",
					Algorithm: "",
					Size:      2048,
				})
			},
			resultCheck: func(createdKey *models.Key, err error) error {
				if err == nil {
					return fmt.Errorf("expected error for missing algorithm, got nil")
				}
				return nil
			},
		},
		{
			name:   "Error/MissingSize",
			before: func(svc services.KMSService) error { return nil },
			run: func(kmsSDK services.KMSService) (*models.Key, error) {
				return kmsSDK.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "No Size",
					Algorithm: "RSA",
					Size:      0,
				})
			},
			resultCheck: func(createdKey *models.Key, err error) error {
				if err == nil {
					return fmt.Errorf("expected error for missing size, got nil")
				}
				return nil
			},
		},
		{
			name:   "Error/EngineNotFound",
			before: func(svc services.KMSService) error { return nil },
			run: func(kmsSDK services.KMSService) (*models.Key, error) {
				return kmsSDK.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "Bad Engine",
					Algorithm: "RSA",
					Size:      2048,
					EngineID:  "nonexistent-engine",
				})
			},
			resultCheck: func(createdKey *models.Key, err error) error {
				if err == nil {
					return fmt.Errorf("expected error for engine not found, got nil")
				}
				return nil
			},
		},
		{
			name:   "Error/InvalidRSAKeySize",
			before: func(svc services.KMSService) error { return nil },
			run: func(kmsSDK services.KMSService) (*models.Key, error) {
				return kmsSDK.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "Small RSA Key",
					Algorithm: "RSA",
					Size:      512,
					EngineID:  "filesystem-1",
				})
			},
			resultCheck: func(createdKey *models.Key, err error) error {
				if err == nil {
					return fmt.Errorf("expected error for invalid RSA key size, got nil")
				}
				return nil
			},
		},
		{
			name:   "Error/InvalidECDSAKeySize",
			before: func(svc services.KMSService) error { return nil },
			run: func(kmsSDK services.KMSService) (*models.Key, error) {
				return kmsSDK.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "Bad ECDSA Size",
					Algorithm: "ECDSA",
					Size:      123,
					EngineID:  "filesystem-1",
				})
			},
			resultCheck: func(createdKey *models.Key, err error) error {
				if err == nil {
					return fmt.Errorf("expected error for invalid ECDSA key size, got nil")
				}
				return nil
			},
		},
		{
			name:   "Error/InvalidMLDSAKeySize",
			before: func(svc services.KMSService) error { return nil },
			run: func(kmsSDK services.KMSService) (*models.Key, error) {
				return kmsSDK.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "Invalid MLDSA key size",
					Algorithm: "ML-DSA",
					Size:      33,
					EngineID:  "filesystem-1",
				})
			},
			resultCheck: func(createdKey *models.Key, err error) error {
				if err == nil {
					return fmt.Errorf("expected error for invalid MLDSA key size, got nil")
				}
				return nil
			},
		},
		{
			name:   "Error/UnsupportedAlgorithm",
			before: func(svc services.KMSService) error { return nil },
			run: func(kmsSDK services.KMSService) (*models.Key, error) {
				return kmsSDK.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "Unknown Algo",
					Algorithm: "FOO",
					Size:      2048,
					EngineID:  "filesystem-1",
				})
			},
			resultCheck: func(createdKey *models.Key, err error) error {
				if err == nil {
					return fmt.Errorf("expected error for unsupported algorithm, got nil")
				}
				return nil
			},
		},
		{
			name:   "OK/KeyType-MLDSA-44",
			before: func(svc services.KMSService) error { return nil },
			run: func(kmsSDK services.KMSService) (*models.Key, error) {
				return kmsSDK.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "Test MLDSA 44 Key",
					Algorithm: "ML-DSA",
					Size:      44,
					EngineID:  "filesystem-1",
				})
			},
			resultCheck: func(createdKey *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should've created MLDSA 44 key without error, but got error: %s", err)
				}
				if createdKey == nil || createdKey.Algorithm != "ML-DSA" || createdKey.Size != 44 {
					return fmt.Errorf("unexpected key result for MLDSA 44: %+v", createdKey)
				}
				return nil
			},
		},
		{
			name:   "OK/KeyType-MLDSA-65",
			before: func(svc services.KMSService) error { return nil },
			run: func(kmsSDK services.KMSService) (*models.Key, error) {
				return kmsSDK.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "Test MLDSA 65 Key",
					Algorithm: "ML-DSA",
					Size:      65,
					EngineID:  "filesystem-1",
				})
			},
			resultCheck: func(createdKey *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should've created MLDSA 65 key without error, but got error: %s", err)
				}
				if createdKey == nil || createdKey.Algorithm != "ML-DSA" || createdKey.Size != 65 {
					return fmt.Errorf("unexpected key result for MLDSA 65: %+v", createdKey)
				}
				return nil
			},
		},
		{
			name:   "OK/KeyType-MLDSA-87",
			before: func(svc services.KMSService) error { return nil },
			run: func(kmsSDK services.KMSService) (*models.Key, error) {
				return kmsSDK.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "Test MLDSA 87 Key",
					Algorithm: "ML-DSA",
					Size:      87,
					EngineID:  "filesystem-1",
				})
			},
			resultCheck: func(createdKey *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should've created MLDSA 87 key without error, but got error: %s", err)
				}
				if createdKey == nil || createdKey.Algorithm != "ML-DSA" || createdKey.Size != 87 {
					return fmt.Errorf("unexpected key result for MLDSA 87: %+v", createdKey)
				}
				return nil
			},
		},
		{
			name:   "OK/KeyType-Ed25519",
			before: func(svc services.KMSService) error { return nil },
			run: func(kmsSDK services.KMSService) (*models.Key, error) {
				return kmsSDK.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "Test Ed25519 Key",
					Algorithm: "Ed25519",
					Size:      256,
					EngineID:  "filesystem-1",
				})
			},
			resultCheck: func(createdKey *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should've created Ed25519 key without error, but got error: %s", err)
				}
				if createdKey == nil || createdKey.Algorithm != "Ed25519" {
					return fmt.Errorf("unexpected key result for Ed25519: %+v", createdKey)
				}
				return nil
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			err = tc.before(kmsTest.Service)

			err = tc.resultCheck(tc.run(kmsTest.HttpKMSSDK))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}

		})
	}
}

func TmestImportKey(t *testing.T) {
	kmsTest, err := StartKMSServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	// Helper functions for generating PEM-encoded private keys
	generateRSA := func(bits int) any {
		priv, _ := rsa.GenerateKey(rand.Reader, bits)
		return priv
	}

	generateECDSA := func(curve elliptic.Curve) any {
		priv, _ := ecdsa.GenerateKey(curve, rand.Reader)
		return priv
	}

	generateMLDSA := func(size int) any {
		var key any

		switch size {
		case 44:
			_, key, _ = mldsa44.GenerateKey(rand.Reader)
		case 65:
			_, key, _ = mldsa65.GenerateKey(rand.Reader)
		case 87:
			_, key, _ = mldsa87.GenerateKey(rand.Reader)
		}

		return key
	}

	generateEd25519 := func() any {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		return key
	}

	testcases := []struct {
		name        string
		before      func()
		run         func() (*models.Key, error)
		resultCheck func(key *models.Key, err error) error
	}{
		{
			name:   "OK/Import-MLDSA-44",
			before: func() {},
			run: func() (*models.Key, error) {
				return kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
					Name:       "MLDSA 44 Key",
					PrivateKey: generateMLDSA(44),
					EngineID:   "filesystem-1",
				})
			},
			resultCheck: func(key *models.Key, err error) error {
				// Replace with real MLDSA key import logic as needed
				if err != nil {
					return fmt.Errorf("should've imported MLDSA 44 key without error, but got: %s", err)
				}
				if key == nil || key.Algorithm != "ML-DSA" || key.Size != 44 {
					return fmt.Errorf("unexpected key result for MLDSA 44 import: %+v", key)
				}
				return nil
			},
		},
		{
			name:   "OK/Import-MLDSA-65",
			before: func() {},
			run: func() (*models.Key, error) {
				return kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
					Name:       "MLDSA 65 Key",
					PrivateKey: generateMLDSA(65),
					EngineID:   "filesystem-1",
				})
			},
			resultCheck: func(key *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should've imported MLDSA 65 key without error, but got: %s", err)
				}
				if key == nil || key.Algorithm != "ML-DSA" || key.Size != 65 {
					return fmt.Errorf("unexpected key result for MLDSA 65 import: %+v", key)
				}
				return nil
			},
		},
		{
			name:   "OK/Import-MLDSA-87",
			before: func() {},
			run: func() (*models.Key, error) {
				return kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
					Name:       "MLDSA 87 Key",
					PrivateKey: generateMLDSA(87),
					EngineID:   "filesystem-1",
				})
			},
			resultCheck: func(key *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should've imported MLDSA 87 key without error, but got: %s", err)
				}
				if key == nil || key.Algorithm != "ML-DSA" || key.Size != 87 {
					return fmt.Errorf("unexpected key result for MLDSA 87 import: %+v", key)
				}
				return nil
			},
		},
		{
			name:   "OK/Import-Ed25519",
			before: func() {},
			run: func() (*models.Key, error) {
				return kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
					Name:       "Ed25519 Key",
					PrivateKey: generateEd25519(),
					EngineID:   "filesystem-1",
				})
			},
			resultCheck: func(key *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should've imported Ed25519 key without error, but got: %s", err)
				}
				if key == nil || key.Algorithm != "Ed25519" {
					return fmt.Errorf("unexpected key result for Ed25519 import: %+v", key)
				}
				return nil
			},
		},
		{
			name:   "OK/Import-RSA",
			before: func() {},
			run: func() (*models.Key, error) {
				return kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
					Name:       "RSA Key",
					PrivateKey: generateRSA(2048),
					EngineID:   "filesystem-1",
				})
			},
			resultCheck: func(key *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should've imported RSA key without error, but got: %s", err)
				}
				if key == nil || key.Algorithm != "RSA" {
					return fmt.Errorf("unexpected key result for RSA import: %+v", key)
				}
				return nil
			},
		},
		{
			name:   "OK/Import-RSA-3072",
			before: func() {},
			run: func() (*models.Key, error) {
				return kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
					Name:       "RSA 3072 Key",
					PrivateKey: generateRSA(3072),
					EngineID:   "filesystem-1",
				})
			},
			resultCheck: func(key *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should've imported RSA 3072 key without error, but got: %s", err)
				}
				if key == nil || key.Algorithm != "RSA" || key.Size != 3072 {
					return fmt.Errorf("unexpected key result for RSA 3072 import: %+v", key)
				}
				return nil
			},
		},
		{
			name:   "OK/Import-RSA-4096",
			before: func() {},
			run: func() (*models.Key, error) {
				return kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
					Name:       "RSA 4096 Key",
					PrivateKey: generateRSA(4096),
					EngineID:   "filesystem-1",
				})
			},
			resultCheck: func(key *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should've imported RSA 4096 key without error, but got: %s", err)
				}
				if key == nil || key.Algorithm != "RSA" || key.Size != 4096 {
					return fmt.Errorf("unexpected key result for RSA 4096 import: %+v", key)
				}
				return nil
			},
		},
		{
			name:   "OK/Import-ECDSA",
			before: func() {},
			run: func() (*models.Key, error) {
				return kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
					Name:       "ECDSA Key",
					PrivateKey: generateECDSA(elliptic.P256()),
					EngineID:   "filesystem-1",
				})
			},
			resultCheck: func(key *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should've imported ECDSA key without error, but got: %s", err)
				}
				if key == nil || key.Algorithm != "ECDSA" {
					return fmt.Errorf("unexpected key result for ECDSA import: %+v", key)
				}
				return nil
			},
		},
		{
			name:   "OK/Import-ECDSA-P224",
			before: func() {},
			run: func() (*models.Key, error) {
				return kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
					Name:       "ECDSA P224 Key",
					PrivateKey: generateECDSA(elliptic.P224()),
					EngineID:   "filesystem-1",
				})
			},
			resultCheck: func(key *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should've imported ECDSA P224 key without error, but got: %s", err)
				}
				if key == nil || key.Algorithm != "ECDSA" || key.Size != 224 {
					return fmt.Errorf("unexpected key result for ECDSA P224 import: %+v", key)
				}
				return nil
			},
		},
		{
			name:   "OK/Import-ECDSA-P384",
			before: func() {},
			run: func() (*models.Key, error) {
				return kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
					Name:       "ECDSA P384 Key",
					PrivateKey: generateECDSA(elliptic.P384()),
					EngineID:   "filesystem-1",
				})
			},
			resultCheck: func(key *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should've imported ECDSA P384 key without error, but got: %s", err)
				}
				if key == nil || key.Algorithm != "ECDSA" || key.Size != 384 {
					return fmt.Errorf("unexpected key result for ECDSA P384 import: %+v", key)
				}
				return nil
			},
		},
		{
			name:   "OK/Import-ECDSA-P521",
			before: func() {},
			run: func() (*models.Key, error) {
				return kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
					Name:       "ECDSA P521 Key",
					PrivateKey: generateECDSA(elliptic.P521()),
					EngineID:   "filesystem-1",
				})
			},
			resultCheck: func(key *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should've imported ECDSA P521 key without error, but got: %s", err)
				}
				if key == nil || key.Algorithm != "ECDSA" || key.Size != 521 {
					return fmt.Errorf("unexpected key result for ECDSA P521 import: %+v", key)
				}
				return nil
			},
		},
		{
			name:   "Error/InvalidPEM",
			before: func() {},
			run: func() (*models.Key, error) {
				return kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
					Name:       "Invalid PEM",
					PrivateKey: []byte("not a pem block"),
					EngineID:   "filesystem-1",
				})
			},
			resultCheck: func(key *models.Key, err error) error {
				if err == nil {
					return fmt.Errorf("expected error for invalid PEM, got nil")
				}
				return nil
			},
		},
		{
			name:   "Error/UnsupportedKeyType",
			before: func() {},
			run: func() (*models.Key, error) {
				return kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
					Name:       "Unsupported Key",
					PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "DSA PRIVATE KEY", Bytes: []byte("dummy")}),
					EngineID:   "filesystem-1",
				})
			},
			resultCheck: func(key *models.Key, err error) error {
				if err == nil {
					return fmt.Errorf("expected error for unsupported key type, got nil")
				}
				return nil
			},
		},
		{
			name:   "Error/EngineNotFound",
			before: func() {},
			run: func() (*models.Key, error) {
				return kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
					Name:       "No Engine",
					PrivateKey: generateRSA(2048),
					EngineID:   "nonexistent-engine",
				})
			},
			resultCheck: func(key *models.Key, err error) error {
				if err == nil {
					return fmt.Errorf("expected error for engine not found, got nil")
				}
				return nil
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tc.before()
			key, err := tc.run()
			err = tc.resultCheck(key, err)
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

func TestGetKeys(t *testing.T) {
	keysIds := [3]string{"ListKey1", "ListKey2", "ListKey3"}
	kmsTest, err := StartKMSServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	// Helper to import a key for listing
	importKey := func(name string, bits int) {
		pem := func(bits int) any {
			priv, _ := rsa.GenerateKey(rand.Reader, bits)
			return priv
		}(bits)
		_, err := kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
			Name:       name,
			PrivateKey: pem,
			EngineID:   "filesystem-1",
		})
		if err != nil {
			t.Fatalf("failed to import key for GetKeys test: %s", err)
		}
	}

	testcases := []struct {
		name        string
		before      func()
		run         func() ([]models.Key, error)
		resultCheck func(keys []models.Key, err error)
	}{
		{
			name: "OK/GetKeys-PaginationWithoutExhaustiveRun",
			before: func() {
				importKey(keysIds[0], 2048)
				importKey(keysIds[1], 3072)
				importKey(keysIds[2], 2048)
			},
			run: func() ([]models.Key, error) {
				keys := []models.Key{}
				request := services.GetKeysInput{
					ListInput: resources.ListInput[models.Key]{
						QueryParameters: &resources.QueryParameters{
							PageSize: 2,
							Sort: resources.SortOptions{
								SortMode:  resources.SortModeAsc,
								SortField: "name",
							},
						},
						ExhaustiveRun: false,
						ApplyFunc: func(key models.Key) {
							keys = append(keys, key)
						},
					},
				}
				_, err := kmsTest.HttpKMSSDK.GetKeys(context.Background(), request)
				return keys, err
			},
			resultCheck: func(keys []models.Key, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}
				if len(keys) != 2 {
					t.Fatalf("expected 2 keys, got %d", len(keys))
				}
				keyTest := keysIds[:2]
				for _, name := range keyTest {
					contains := slices.ContainsFunc(keys, func(key models.Key) bool {
						return key.Name == name
					})
					if !contains {
						t.Fatalf("expected key with name %s not found", name)
					}
				}
			},
		},
		{
			name: "OK/GetKeys-ExhaustiveRun",
			before: func() {
				// Already imported in previous test
			},
			run: func() ([]models.Key, error) {
				keys := []models.Key{}
				request := services.GetKeysInput{
					ListInput: resources.ListInput[models.Key]{
						QueryParameters: &resources.QueryParameters{},
						ExhaustiveRun:   true,
						ApplyFunc: func(key models.Key) {
							keys = append(keys, key)
						},
					},
				}
				_, err := kmsTest.HttpKMSSDK.GetKeys(context.Background(), request)
				return keys, err
			},
			resultCheck: func(keys []models.Key, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}
				if len(keys) < 3 {
					t.Fatalf("expected at least 3 keys, got %d", len(keys))
				}
			},
		},
		{
			name:   "OK/GetKeys-EmptyResult",
			before: func() {},
			run: func() ([]models.Key, error) {
				keys := []models.Key{}
				request := services.GetKeysInput{
					ListInput: resources.ListInput[models.Key]{
						QueryParameters: &resources.QueryParameters{
							Filters: []resources.FilterOption{{Field: "name", FilterOperation: resources.StringEqual, Value: "no-such-key"}},
						},
						ExhaustiveRun: true,
						ApplyFunc: func(key models.Key) {
							keys = append(keys, key)
						},
					},
				}
				_, err := kmsTest.HttpKMSSDK.GetKeys(context.Background(), request)
				return keys, err
			},
			resultCheck: func(keys []models.Key, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}
				if len(keys) != 0 {
					t.Fatalf("expected 0 keys, got %d", len(keys))
				}
			},
		},
		{
			name:   "Error/GetKeys-InvalidContext",
			before: func() {},
			run: func() ([]models.Key, error) {
				keys := []models.Key{}
				request := services.GetKeysInput{
					ListInput: resources.ListInput[models.Key]{
						QueryParameters: &resources.QueryParameters{},
						ExhaustiveRun:   true,
						ApplyFunc: func(key models.Key) {
							keys = append(keys, key)
						},
					},
				}
				_, err := kmsTest.HttpKMSSDK.GetKeys(nil, request)
				return keys, err
			},
			resultCheck: func(keys []models.Key, err error) {
				if err == nil {
					t.Fatalf("expected error for invalid context, got nil")
				}
			},
		},
		{
			name:   "OK/GetKeys-SortingDesc",
			before: func() {},
			run: func() ([]models.Key, error) {
				keys := []models.Key{}
				request := services.GetKeysInput{
					ListInput: resources.ListInput[models.Key]{
						QueryParameters: &resources.QueryParameters{
							PageSize: 3,
							Sort: resources.SortOptions{
								SortMode:  resources.SortModeDesc,
								SortField: "name",
							},
						},
						ExhaustiveRun: false,
						ApplyFunc: func(key models.Key) {
							keys = append(keys, key)
						},
					},
				}
				_, err := kmsTest.HttpKMSSDK.GetKeys(context.Background(), request)
				return keys, err
			},
			resultCheck: func(keys []models.Key, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}
				if len(keys) != 3 {
					t.Fatalf("expected 3 keys, got %d", len(keys))
				}
				// Check descending order
				if !(keys[0].Name > keys[1].Name && keys[1].Name > keys[2].Name) {
					t.Fatalf("keys are not sorted in descending order by name")
				}
			},
		},
	}

	for _, tc := range testcases {
		tc.before()
		t.Run(tc.name, func(t *testing.T) {
			tc.resultCheck(tc.run())
		})
	}
}

func TestGetKey(t *testing.T) {
	kmsTest, err := StartKMSServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	// Helper to import a key and return its ID
	importKey := func(name string, bits int) string {
		pem := func(bits int) any {
			priv, _ := rsa.GenerateKey(rand.Reader, bits)
			return priv
		}(bits)
		key, err := kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
			Name:       name,
			PrivateKey: pem,
			EngineID:   "filesystem-1",
		})
		if err != nil {
			t.Fatalf("failed to import key for GetKey test: %s", err)
		}
		return key.PKCS11URI
	}

	var validKeyID string

	testcases := []struct {
		name        string
		before      func()
		run         func() (*models.Key, error)
		resultCheck func(key *models.Key, err error) error
	}{
		{
			name: "OK/GetKey-Valid",
			before: func() {
				validKeyID = importKey("KeyByID", 2048)
			},
			run: func() (*models.Key, error) {
				return kmsTest.HttpKMSSDK.GetKey(context.Background(), services.GetKeyInput{Identifier: validKeyID})
			},
			resultCheck: func(key *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should not error on GetKey: %s", err)
				}
				if key == nil || key.PKCS11URI != validKeyID {
					return fmt.Errorf("unexpected key result for GetKey: %+v", key)
				}
				return nil
			},
		},
		{
			name:   "Error/GetKey-NotFound",
			before: func() {},
			run: func() (*models.Key, error) {
				return kmsTest.HttpKMSSDK.GetKey(context.Background(), services.GetKeyInput{Identifier: "nonexistent-key-id"})
			},
			resultCheck: func(key *models.Key, err error) error {
				if err == nil {
					return fmt.Errorf("expected error for not found key, got nil")
				}
				return nil
			},
		},
		{
			name:   "Error/GetKey-InvalidContext",
			before: func() {},
			run: func() (*models.Key, error) {
				return kmsTest.HttpKMSSDK.GetKey(nil, services.GetKeyInput{Identifier: "any-id"})
			},
			resultCheck: func(key *models.Key, err error) error {
				if err == nil {
					return fmt.Errorf("expected error for invalid context, got nil")
				}
				return nil
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tc.before()
			key, err := tc.run()
			err = tc.resultCheck(key, err)
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

func TestDeleteKeyByID(t *testing.T) {
	kmsTest, err := StartKMSServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	// Helper to import a key and return its ID
	importKey := func(name string, bits int) string {
		pem := func(bits int) any {
			priv, _ := rsa.GenerateKey(rand.Reader, bits)
			return priv
		}(bits)
		key, err := kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
			Name:       name,
			PrivateKey: pem,
			EngineID:   "filesystem-1",
		})
		if err != nil {
			t.Fatalf("failed to import key for DeleteKeyByID test: %s", err)
		}
		return key.PKCS11URI
	}

	var validKeyID string

	testcases := []struct {
		name        string
		before      func()
		run         func() error
		resultCheck func(err error) error
	}{
		{
			name: "OK/DeleteKeyByID-Valid",
			before: func() {
				validKeyID = importKey("KeyToDelete", 2048)
			},
			run: func() error {
				return kmsTest.HttpKMSSDK.DeleteKeyByID(context.Background(), services.GetKeyInput{Identifier: validKeyID})
			},
			resultCheck: func(err error) error {
				if err != nil {
					return fmt.Errorf("should not error on DeleteKeyByIdentifier:%s", err)
				}
				// Try to get the key, should not be found
				_, getErr := kmsTest.HttpKMSSDK.GetKey(context.Background(), services.GetKeyInput{Identifier: validKeyID})
				if getErr == nil {
					return fmt.Errorf("expected error when getting deleted key, got nil")
				}
				return nil
			},
		},
		{
			name:   "Error/DeleteKeyByID-NotFound",
			before: func() {},
			run: func() error {
				return kmsTest.HttpKMSSDK.DeleteKeyByID(context.Background(), services.GetKeyInput{Identifier: "nonexistent-key-id"})
			},
			resultCheck: func(err error) error {
				if err == nil {
					return fmt.Errorf("expected error for not found key, got nil")
				}
				return nil
			},
		},
		{
			name:   "Error/DeleteKeyByID-InvalidContext",
			before: func() {},
			run: func() error {
				return kmsTest.HttpKMSSDK.DeleteKeyByID(nil, services.GetKeyInput{Identifier: "any-id"})
			},
			resultCheck: func(err error) error {
				if err == nil {
					return fmt.Errorf("expected error for invalid context, got nil")
				}
				return nil
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tc.before()
			err := tc.run()
			err = tc.resultCheck(err)
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

func TestSignMessage(t *testing.T) {
	kmsTest, err := StartKMSServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	// Helper to import a key and return its ID and algorithm
	importKey := func(name string, bits int) (string, string) {
		b64Key := func(bits int) any {
			priv, _ := rsa.GenerateKey(rand.Reader, bits)
			return priv
		}(bits)
		key, err := kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
			Name:       name,
			PrivateKey: b64Key,
			EngineID:   "filesystem-1",
		})
		if err != nil {
			t.Fatalf("failed to import key for SignMessage test: %s", err)
		}
		return key.PKCS11URI, key.Algorithm
	}

	var validKeyID string
	var validAlgorithm string
	var message = []byte("test message")

	testcases := []struct {
		name        string
		before      func()
		run         func() (*models.MessageSignature, error)
		resultCheck func(sig *models.MessageSignature, err error) error
	}{
		{
			name: "OK/SignMessage-MLDSA-44",
			before: func() {
				_, priv, _ := mldsa44.GenerateKey(rand.Reader)
				key, err := kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
					Name:       "SignMLDSA44",
					PrivateKey: priv,
					EngineID:   "filesystem-1",
				})
				if err != nil {
					panic(fmt.Sprintf("failed to import MLDSA-44 key: %s", err))
				}
				validKeyID = key.PKCS11URI
			},
			run: func() (*models.MessageSignature, error) {
				return kmsTest.HttpKMSSDK.SignMessage(context.Background(), services.SignMessageInput{
					Identifier:  validKeyID,
					Message:     message,
					Algorithm:   "MLDSA_44_PURE",
					MessageType: models.Raw,
				})
			},
			resultCheck: func(sig *models.MessageSignature, err error) error {
				if err != nil {
					return fmt.Errorf("should not error on SignMessage MLDSA-44: %s", err)
				}
				if sig == nil || len(sig.Signature) == 0 {
					return fmt.Errorf("expected signature, got nil or empty")
				}
				return nil
			},
		},
		{
			name: "OK/SignMessage-MLDSA-65",
			before: func() {
				_, priv, _ := mldsa65.GenerateKey(rand.Reader)
				key, err := kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
					Name:       "SignMLDSA65",
					PrivateKey: priv,
					EngineID:   "filesystem-1",
				})
				if err != nil {
					panic(fmt.Sprintf("failed to import MLDSA-65 key: %s", err))
				}
				validKeyID = key.PKCS11URI
			},
			run: func() (*models.MessageSignature, error) {
				return kmsTest.HttpKMSSDK.SignMessage(context.Background(), services.SignMessageInput{
					Identifier:  validKeyID,
					Message:     message,
					Algorithm:   "MLDSA_65_PURE",
					MessageType: models.Raw,
				})
			},
			resultCheck: func(sig *models.MessageSignature, err error) error {
				if err != nil {
					return fmt.Errorf("should not error on SignMessage MLDSA-65: %s", err)
				}
				if sig == nil || len(sig.Signature) == 0 {
					return fmt.Errorf("expected signature, got nil or empty")
				}
				return nil
			},
		},
		{
			name: "OK/SignMessage-MLDSA-87",
			before: func() {
				_, priv, _ := mldsa87.GenerateKey(rand.Reader)
				key, err := kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
					Name:       "SignMLDSA87",
					PrivateKey: priv,
					EngineID:   "filesystem-1",
				})
				if err != nil {
					panic(fmt.Sprintf("failed to import MLDSA-87 key: %s", err))
				}
				validKeyID = key.PKCS11URI
			},
			run: func() (*models.MessageSignature, error) {
				return kmsTest.HttpKMSSDK.SignMessage(context.Background(), services.SignMessageInput{
					Identifier:  validKeyID,
					Message:     message,
					Algorithm:   "MLDSA_87_PURE",
					MessageType: models.Raw,
				})
			},
			resultCheck: func(sig *models.MessageSignature, err error) error {
				if err != nil {
					return fmt.Errorf("should not error on SignMessage MLDSA-87: %s", err)
				}
				if sig == nil || len(sig.Signature) == 0 {
					return fmt.Errorf("expected signature, got nil or empty")
				}
				return nil
			},
		},
		{
			name: "OK/SignMessage-Ed25519",
			before: func() {
				_, priv, _ := ed25519.GenerateKey(rand.Reader)
				key, err := kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
					Name:       "SignEd25519",
					PrivateKey: priv,
					EngineID:   "filesystem-1",
				})
				if err != nil {
					panic(fmt.Sprintf("failed to import Ed25519 key: %s", err))
				}
				validKeyID = key.PKCS11URI
			},
			run: func() (*models.MessageSignature, error) {
				return kmsTest.HttpKMSSDK.SignMessage(context.Background(), services.SignMessageInput{
					Identifier:  validKeyID,
					Message:     message,
					Algorithm:   "Ed25519_PURE",
					MessageType: models.Raw,
				})
			},
			resultCheck: func(sig *models.MessageSignature, err error) error {
				if err != nil {
					return fmt.Errorf("should not error on SignMessage Ed25519: %s", err)
				}
				if sig == nil || len(sig.Signature) == 0 {
					return fmt.Errorf("expected signature, got nil or empty")
				}
				return nil
			},
		},
		{
			name: "OK/SignMessage-Valid",
			before: func() {
				validKeyID, validAlgorithm = importKey("SignKey", 2048)
			},
			run: func() (*models.MessageSignature, error) {
				fmt.Println("Signing message with key ID:", validKeyID, "and algorithm:", validAlgorithm)
				return kmsTest.HttpKMSSDK.SignMessage(context.Background(), services.SignMessageInput{
					Identifier:  validKeyID,
					Message:     message,
					Algorithm:   "RSASSA_PKCS1_V1_5_SHA_512",
					MessageType: models.Raw,
				})
			},
			resultCheck: func(sig *models.MessageSignature, err error) error {
				if err != nil {
					return fmt.Errorf("should not error on SignMessage: %s", err)
				}
				if sig == nil || len(sig.Signature) == 0 {
					return fmt.Errorf("expected signature, got nil or empty")
				}
				return nil
			},
		},
		{
			name:   "Error/SignMessage-KeyNotFound",
			before: func() {},
			run: func() (*models.MessageSignature, error) {
				return kmsTest.HttpKMSSDK.SignMessage(context.Background(), services.SignMessageInput{
					Identifier:  "nonexistent-key-id",
					Message:     message,
					Algorithm:   "RSA",
					MessageType: models.Raw,
				})
			},
			resultCheck: func(sig *models.MessageSignature, err error) error {
				if err == nil {
					return fmt.Errorf("expected error for not found key, got nil")
				}
				return nil
			},
		},
		{
			name:   "Error/SignMessage-InvalidContext",
			before: func() {},
			run: func() (*models.MessageSignature, error) {
				return kmsTest.HttpKMSSDK.SignMessage(nil, services.SignMessageInput{
					Identifier:  "any-id",
					Message:     message,
					Algorithm:   "RSA",
					MessageType: models.Raw,
				})
			},
			resultCheck: func(sig *models.MessageSignature, err error) error {
				if err == nil {
					return fmt.Errorf("expected error for invalid context, got nil")
				}
				return nil
			},
		},
		{
			name: "Error/SignMessage-EmptyMessage",
			before: func() {
				validKeyID, validAlgorithm = importKey("SignKey2", 2048)
			},
			run: func() (*models.MessageSignature, error) {
				return kmsTest.HttpKMSSDK.SignMessage(context.Background(), services.SignMessageInput{
					Identifier:  validKeyID,
					Message:     []byte{},
					Algorithm:   validAlgorithm,
					MessageType: models.Raw,
				})
			},
			resultCheck: func(sig *models.MessageSignature, err error) error {
				if err == nil {
					return fmt.Errorf("expected error for empty message, got nil")
				}
				return nil
			},
		},
		{
			name: "Error/SignMessage-HashType-InvalidHashLength",
			before: func() {
				validKeyID, validAlgorithm = importKey("SignKey3", 2048)
			},
			run: func() (*models.MessageSignature, error) {
				// Using SHA-256 algorithm but providing incorrect hash length
				// SHA-256 expects 32 bytes, but we provide 16 bytes
				invalidHashMessage := make([]byte, 16) // Wrong length for SHA-256
				return kmsTest.HttpKMSSDK.SignMessage(context.Background(), services.SignMessageInput{
					Identifier:  validKeyID,
					Message:     invalidHashMessage,
					Algorithm:   "RSASSA_PKCS1_V1_5_SHA_256", // SHA-256 expects 32 bytes
					MessageType: models.Hashed,               // This should trigger hash length validation
				})
			},
			resultCheck: func(sig *models.MessageSignature, err error) error {
				if err == nil {
					return fmt.Errorf("expected error for invalid hash length when MessageType is Hash, got nil")
				}
				expectedErrMsg := "invalid digest size"
				if !strings.Contains(err.Error(), expectedErrMsg) {
					return fmt.Errorf("expected error to contain '%s', but got: %s", expectedErrMsg, err.Error())
				}
				return nil
			},
		},
		{
			name: "OK/SignMessage-HashType-ValidHashLength",
			before: func() {
				validKeyID, validAlgorithm = importKey("SignKey4", 2048)
			},
			run: func() (*models.MessageSignature, error) {
				// Using SHA-256 algorithm with correct hash length (32 bytes)
				validHashMessage := make([]byte, 32) // Correct length for SHA-256
				// Fill with some test data
				for i := range validHashMessage {
					validHashMessage[i] = byte(i % 256)
				}
				return kmsTest.HttpKMSSDK.SignMessage(context.Background(), services.SignMessageInput{
					Identifier:  validKeyID,
					Message:     validHashMessage,
					Algorithm:   "RSASSA_PKCS1_V1_5_SHA_256", // SHA-256 expects 32 bytes
					MessageType: models.Hashed,               // This should pass hash length validation
				})
			},
			resultCheck: func(sig *models.MessageSignature, err error) error {
				if err != nil {
					return fmt.Errorf("should not error when providing correct hash length for MessageType Hash: %s", err)
				}
				if sig == nil || len(sig.Signature) == 0 {
					return fmt.Errorf("expected signature, got nil or empty")
				}
				return nil
			},
		},
		{
			name: "Error/SignMessage-ECDSA256-WrongHashSize",
			before: func() {
				// Create ECDSA-256 key
				pem := func() any {
					priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					return priv
				}()
				key, err := kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
					Name:       "ECDSA256-WrongHash",
					PrivateKey: pem,
					EngineID:   "filesystem-1",
				})
				if err != nil {
					panic(fmt.Sprintf("failed to import ECDSA-256 key: %s", err))
				}
				validKeyID = key.PKCS11URI
			},
			run: func() (*models.MessageSignature, error) {
				// Using ECDSA_SHA_256 but providing SHA-384 hash length (48 bytes instead of 32)
				wrongHashMessage := make([]byte, 48) // Wrong length for ECDSA_SHA_256
				return kmsTest.HttpKMSSDK.SignMessage(context.Background(), services.SignMessageInput{
					Identifier:  validKeyID,
					Message:     wrongHashMessage,
					Algorithm:   "ECDSA_SHA_256", // SHA-256 expects 32 bytes, not 48
					MessageType: models.Hashed,
				})
			},
			resultCheck: func(sig *models.MessageSignature, err error) error {
				if err == nil {
					return fmt.Errorf("expected error for ECDSA-256 key with wrong hash size, got nil")
				}
				expectedErrMsg := "invalid digest size"
				if !strings.Contains(err.Error(), expectedErrMsg) {
					return fmt.Errorf("expected error to contain '%s', but got: %s", expectedErrMsg, err.Error())
				}
				return nil
			},
		},
		{
			name: "OK/SignMessage-ECDSA256-CorrectHashSize",
			before: func() {
				// Create ECDSA-256 key
				pem := func() any {
					priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					return priv
				}()
				key, err := kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
					Name:       "ECDSA256-CorrectHash",
					PrivateKey: pem,
					EngineID:   "filesystem-1",
				})
				if err != nil {
					panic(fmt.Sprintf("failed to import ECDSA-256 key: %s", err))
				}
				validKeyID = key.PKCS11URI
			},
			run: func() (*models.MessageSignature, error) {
				// Using ECDSA_SHA_256 with correct hash length (32 bytes)
				correctHashMessage := make([]byte, 32) // Correct length for ECDSA_SHA_256
				for i := range correctHashMessage {
					correctHashMessage[i] = byte(i % 256)
				}
				return kmsTest.HttpKMSSDK.SignMessage(context.Background(), services.SignMessageInput{
					Identifier:  validKeyID,
					Message:     correctHashMessage,
					Algorithm:   "ECDSA_SHA_256", // SHA-256 expects 32 bytes
					MessageType: models.Hashed,
				})
			},
			resultCheck: func(sig *models.MessageSignature, err error) error {
				if err != nil {
					return fmt.Errorf("should not error for ECDSA-256 key with correct hash size: %s", err)
				}
				if sig == nil || len(sig.Signature) == 0 {
					return fmt.Errorf("expected signature, got nil or empty")
				}
				return nil
			},
		},
		{
			name: "Error/SignMessage-ECDSA384-WrongHashSize",
			before: func() {
				// Create ECDSA-384 key
				pem := func() any {
					priv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
					return priv
				}()
				key, err := kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
					Name:       "ECDSA384-WrongHash",
					PrivateKey: pem,
					EngineID:   "filesystem-1",
				})
				if err != nil {
					panic(fmt.Sprintf("failed to import ECDSA-384 key: %s", err))
				}
				validKeyID = key.PKCS11URI
			},
			run: func() (*models.MessageSignature, error) {
				// Using ECDSA_SHA_384 but providing SHA-256 hash length (32 bytes instead of 48)
				wrongHashMessage := make([]byte, 32) // Wrong length for ECDSA_SHA_384
				return kmsTest.HttpKMSSDK.SignMessage(context.Background(), services.SignMessageInput{
					Identifier:  validKeyID,
					Message:     wrongHashMessage,
					Algorithm:   "ECDSA_SHA_384", // SHA-384 expects 48 bytes, not 32
					MessageType: models.Hashed,
				})
			},
			resultCheck: func(sig *models.MessageSignature, err error) error {
				if err == nil {
					return fmt.Errorf("expected error for ECDSA-384 key with wrong hash size, got nil")
				}
				expectedErrMsg := "invalid digest size"
				if !strings.Contains(err.Error(), expectedErrMsg) {
					return fmt.Errorf("expected error to contain '%s', but got: %s", expectedErrMsg, err.Error())
				}
				return nil
			},
		},
		{
			name: "OK/SignMessage-ECDSA384-CorrectHashSize",
			before: func() {
				// Create ECDSA-384 key
				pem := func() any {
					priv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
					return priv
				}()
				key, err := kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
					Name:       "ECDSA384-CorrectHash",
					PrivateKey: pem,
					EngineID:   "filesystem-1",
				})
				if err != nil {
					panic(fmt.Sprintf("failed to import ECDSA-384 key: %s", err))
				}
				validKeyID = key.PKCS11URI
			},
			run: func() (*models.MessageSignature, error) {
				// Using ECDSA_SHA_384 with correct hash length (48 bytes)
				correctHashMessage := make([]byte, 48) // Correct length for ECDSA_SHA_384
				for i := range correctHashMessage {
					correctHashMessage[i] = byte(i % 256)
				}
				return kmsTest.HttpKMSSDK.SignMessage(context.Background(), services.SignMessageInput{
					Identifier:  validKeyID,
					Message:     correctHashMessage,
					Algorithm:   "ECDSA_SHA_384", // SHA-384 expects 48 bytes
					MessageType: models.Hashed,
				})
			},
			resultCheck: func(sig *models.MessageSignature, err error) error {
				if err != nil {
					return fmt.Errorf("should not error for ECDSA-384 key with correct hash size: %s", err)
				}
				if sig == nil || len(sig.Signature) == 0 {
					return fmt.Errorf("expected signature, got nil or empty")
				}
				return nil
			},
		},
		{
			name: "Error/SignMessage-ECDSA521-WrongHashSize",
			before: func() {
				// Create ECDSA-521 key
				pem := func() any {
					priv, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
					return priv
				}()
				key, err := kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
					Name:       "ECDSA521-WrongHash",
					PrivateKey: pem,
					EngineID:   "filesystem-1",
				})
				if err != nil {
					panic(fmt.Sprintf("failed to import ECDSA-521 key: %s", err))
				}
				validKeyID = key.PKCS11URI
			},
			run: func() (*models.MessageSignature, error) {
				// Using ECDSA_SHA_512 but providing SHA-384 hash length (48 bytes instead of 64)
				wrongHashMessage := make([]byte, 48) // Wrong length for ECDSA_SHA_512
				return kmsTest.HttpKMSSDK.SignMessage(context.Background(), services.SignMessageInput{
					Identifier:  validKeyID,
					Message:     wrongHashMessage,
					Algorithm:   "ECDSA_SHA_512", // SHA-512 expects 64 bytes, not 48
					MessageType: models.Hashed,
				})
			},
			resultCheck: func(sig *models.MessageSignature, err error) error {
				if err == nil {
					return fmt.Errorf("expected error for ECDSA-521 key with wrong hash size, got nil")
				}
				expectedErrMsg := "invalid digest size"
				if !strings.Contains(err.Error(), expectedErrMsg) {
					return fmt.Errorf("expected error to contain '%s', but got: %s", expectedErrMsg, err.Error())
				}
				return nil
			},
		},
		{
			name: "OK/SignMessage-ECDSA521-CorrectHashSize",
			before: func() {
				// Create ECDSA-521 key
				pem := func() any {
					priv, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
					return priv
				}()
				key, err := kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
					Name:       "ECDSA521-CorrectHash",
					PrivateKey: pem,
					EngineID:   "filesystem-1",
				})
				if err != nil {
					panic(fmt.Sprintf("failed to import ECDSA-521 key: %s", err))
				}
				validKeyID = key.PKCS11URI
			},
			run: func() (*models.MessageSignature, error) {
				// Using ECDSA_SHA_512 with correct hash length (64 bytes)
				correctHashMessage := make([]byte, 64) // Correct length for ECDSA_SHA_512
				for i := range correctHashMessage {
					correctHashMessage[i] = byte(i % 256)
				}
				return kmsTest.HttpKMSSDK.SignMessage(context.Background(), services.SignMessageInput{
					Identifier:  validKeyID,
					Message:     correctHashMessage,
					Algorithm:   "ECDSA_SHA_512", // SHA-512 expects 64 bytes
					MessageType: models.Hashed,
				})
			},
			resultCheck: func(sig *models.MessageSignature, err error) error {
				if err != nil {
					return fmt.Errorf("should not error for ECDSA-521 key with correct hash size: %s", err)
				}
				if sig == nil || len(sig.Signature) == 0 {
					return fmt.Errorf("expected signature, got nil or empty")
				}
				return nil
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tc.before()
			sig, err := tc.run()
			err = tc.resultCheck(sig, err)
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

func TestVerifySignature(t *testing.T) {
	kmsTest, err := StartKMSServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	// Helper to import a key, sign a message, and return keyID, algorithm, message, signature ([]byte)
	importAndSign := func(name string, bits int, alg string, msg []byte) (string, string, []byte, []byte) {
		pem := func(bits int) any {
			priv, _ := rsa.GenerateKey(rand.Reader, bits)
			return priv
		}(bits)
		key, err := kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
			Name:       name,
			PrivateKey: pem,
			EngineID:   "filesystem-1",
		})
		if err != nil {
			t.Fatalf("failed to import key for VerifySignature test: %s", err)
		}
		sig, err := kmsTest.HttpKMSSDK.SignMessage(context.Background(), services.SignMessageInput{
			Identifier:  key.PKCS11URI,
			Message:     msg,
			Algorithm:   alg,
			MessageType: models.Raw,
		})
		if err != nil {
			t.Fatalf("failed to sign message for VerifySignature test: %s", err)
		}
		return key.PKCS11URI, alg, msg, sig.Signature
	}

	var validKeyID string
	var validAlgorithm string
	var validMessage []byte
	var validSignature []byte

	testcases := []struct {
		name        string
		before      func()
		run         func() (*models.MessageValidation, error)
		resultCheck func(ok *models.MessageValidation, err error) error
	}{
		{
			name: "OK/VerifySignature-MLDSA-44",
			before: func() {
				_, priv, _ := mldsa44.GenerateKey(rand.Reader)
				key, err := kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
					Name:       "VerifyMLDSA44",
					PrivateKey: priv,
					EngineID:   "filesystem-1",
				})
				if err != nil {
					panic(fmt.Sprintf("failed to import MLDSA-44 key: %s", err))
				}
				validKeyID = key.PKCS11URI
				validAlgorithm = "MLDSA_44_PURE"
				validMessage = []byte("verify mldsa 44")
				sig, err := kmsTest.HttpKMSSDK.SignMessage(context.Background(), services.SignMessageInput{
					Identifier:  validKeyID,
					Message:     validMessage,
					Algorithm:   validAlgorithm,
					MessageType: models.Raw,
				})
				if err != nil {
					panic(fmt.Sprintf("failed to sign with MLDSA-44: %s", err))
				}
				validSignature = sig.Signature
			},
			run: func() (*models.MessageValidation, error) {
				return kmsTest.HttpKMSSDK.VerifySignature(context.Background(), services.VerifySignInput{
					Identifier:  validKeyID,
					Message:     validMessage,
					Algorithm:   validAlgorithm,
					MessageType: models.Raw,
					Signature:   validSignature,
				})
			},
			resultCheck: func(ok *models.MessageValidation, err error) error {
				if err != nil {
					return fmt.Errorf("should not error on VerifySignature MLDSA-44: %s", err)
				}
				if !ok.Valid {
					return fmt.Errorf("expected signature to verify for MLDSA-44, got false")
				}
				return nil
			},
		},
		{
			name: "OK/VerifySignature-MLDSA-65",
			before: func() {
				_, priv, _ := mldsa65.GenerateKey(rand.Reader)
				key, err := kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
					Name:       "VerifyMLDSA65",
					PrivateKey: priv,
					EngineID:   "filesystem-1",
				})
				if err != nil {
					panic(fmt.Sprintf("failed to import MLDSA-65 key: %s", err))
				}
				validKeyID = key.PKCS11URI
				validAlgorithm = "MLDSA_65_PURE"
				validMessage = []byte("verify mldsa 65")
				sig, err := kmsTest.HttpKMSSDK.SignMessage(context.Background(), services.SignMessageInput{
					Identifier:  validKeyID,
					Message:     validMessage,
					Algorithm:   validAlgorithm,
					MessageType: models.Raw,
				})
				if err != nil {
					panic(fmt.Sprintf("failed to sign with MLDSA-65: %s", err))
				}
				validSignature = sig.Signature
			},
			run: func() (*models.MessageValidation, error) {
				return kmsTest.HttpKMSSDK.VerifySignature(context.Background(), services.VerifySignInput{
					Identifier:  validKeyID,
					Message:     validMessage,
					Algorithm:   validAlgorithm,
					MessageType: models.Raw,
					Signature:   validSignature,
				})
			},
			resultCheck: func(ok *models.MessageValidation, err error) error {
				if err != nil {
					return fmt.Errorf("should not error on VerifySignature MLDSA-65: %s", err)
				}
				if !ok.Valid {
					return fmt.Errorf("expected signature to verify for MLDSA-65, got false")
				}
				return nil
			},
		},
		{
			name: "OK/VerifySignature-MLDSA-87",
			before: func() {
				_, priv, _ := mldsa87.GenerateKey(rand.Reader)
				key, err := kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
					Name:       "VerifyMLDSA87",
					PrivateKey: priv,
					EngineID:   "filesystem-1",
				})
				if err != nil {
					panic(fmt.Sprintf("failed to import MLDSA-87 key: %s", err))
				}
				validKeyID = key.PKCS11URI
				validAlgorithm = "MLDSA_87_PURE"
				validMessage = []byte("verify mldsa 87")
				sig, err := kmsTest.HttpKMSSDK.SignMessage(context.Background(), services.SignMessageInput{
					Identifier:  validKeyID,
					Message:     validMessage,
					Algorithm:   validAlgorithm,
					MessageType: models.Raw,
				})
				if err != nil {
					panic(fmt.Sprintf("failed to sign with MLDSA-87: %s", err))
				}
				validSignature = sig.Signature
			},
			run: func() (*models.MessageValidation, error) {
				return kmsTest.HttpKMSSDK.VerifySignature(context.Background(), services.VerifySignInput{
					Identifier:  validKeyID,
					Message:     validMessage,
					Algorithm:   validAlgorithm,
					MessageType: models.Raw,
					Signature:   validSignature,
				})
			},
			resultCheck: func(ok *models.MessageValidation, err error) error {
				if err != nil {
					return fmt.Errorf("should not error on VerifySignature MLDSA-87: %s", err)
				}
				if !ok.Valid {
					return fmt.Errorf("expected signature to verify for MLDSA-87, got false")
				}
				return nil
			},
		},
		{
			name: "OK/VerifySignature-Ed25519",
			before: func() {
				_, priv, _ := ed25519.GenerateKey(rand.Reader)
				key, err := kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
					Name:       "VerifyEd25519",
					PrivateKey: priv,
					EngineID:   "filesystem-1",
				})
				if err != nil {
					panic(fmt.Sprintf("failed to import Ed25519 key: %s", err))
				}
				validKeyID = key.PKCS11URI
				validAlgorithm = "Ed25519_PURE"
				validMessage = []byte("verify ed25519")
				sig, err := kmsTest.HttpKMSSDK.SignMessage(context.Background(), services.SignMessageInput{
					Identifier:  validKeyID,
					Message:     validMessage,
					Algorithm:   validAlgorithm,
					MessageType: models.Raw,
				})
				if err != nil {
					panic(fmt.Sprintf("failed to sign with Ed25519: %s", err))
				}
				validSignature = sig.Signature
			},
			run: func() (*models.MessageValidation, error) {
				return kmsTest.HttpKMSSDK.VerifySignature(context.Background(), services.VerifySignInput{
					Identifier:  validKeyID,
					Message:     validMessage,
					Algorithm:   validAlgorithm,
					MessageType: models.Raw,
					Signature:   validSignature,
				})
			},
			resultCheck: func(ok *models.MessageValidation, err error) error {
				if err != nil {
					return fmt.Errorf("should not error on VerifySignature Ed25519: %s", err)
				}
				if !ok.Valid {
					return fmt.Errorf("expected signature to verify for Ed25519, got false")
				}
				return nil
			},
		},
		{
			name: "OK/VerifySignature-Valid",
			before: func() {
				validMessage = []byte("verify me!")
				validKeyID, validAlgorithm, _, validSignature = importAndSign("VerifyKey", 2048, "RSASSA_PKCS1_V1_5_SHA_512", validMessage)
			},
			run: func() (*models.MessageValidation, error) {
				return kmsTest.HttpKMSSDK.VerifySignature(context.Background(), services.VerifySignInput{
					Identifier:  validKeyID,
					Message:     validMessage,
					Algorithm:   "RSASSA_PKCS1_V1_5_SHA_512",
					MessageType: models.Raw,
					Signature:   validSignature,
				})
			},
			resultCheck: func(ok *models.MessageValidation, err error) error {
				if err != nil {
					return fmt.Errorf("should not error on VerifySignature: %s", err)
				}
				if !ok.Valid {
					return fmt.Errorf("expected signature to verify, got false")
				}
				return nil
			},
		},
		{
			name:   "Error/VerifySignature-KeyNotFound",
			before: func() {},
			run: func() (*models.MessageValidation, error) {
				return kmsTest.HttpKMSSDK.VerifySignature(context.Background(), services.VerifySignInput{
					Identifier:  "nonexistent-key-id",
					Message:     []byte("msg"),
					Algorithm:   "RSASSA_PKCS1_V1_5_SHA_512",
					MessageType: models.Raw,
					Signature:   []byte("sig"),
				})
			},
			resultCheck: func(ok *models.MessageValidation, err error) error {
				if err == nil {
					return fmt.Errorf("expected error for not found key, got nil")
				}
				return nil
			},
		},
		{
			name:   "Error/VerifySignature-InvalidContext",
			before: func() {},
			run: func() (*models.MessageValidation, error) {
				return kmsTest.HttpKMSSDK.VerifySignature(nil, services.VerifySignInput{
					Identifier:  "any-id",
					Message:     []byte("msg"),
					Algorithm:   "RSASSA_PKCS1_V1_5_SHA_512",
					MessageType: models.Raw,
					Signature:   []byte("sig"),
				})
			},
			resultCheck: func(ok *models.MessageValidation, err error) error {
				if err == nil {
					return fmt.Errorf("expected error for invalid context, got nil")
				}
				return nil
			},
		},
		{
			name: "Error/VerifySignature-EmptyMessage",
			before: func() {
				validMessage = []byte("")
				validKeyID, validAlgorithm, _, validSignature = importAndSign("VerifyKey2", 2048, "RSASSA_PKCS1_V1_5_SHA_512", []byte("nonempty"))
			},
			run: func() (*models.MessageValidation, error) {
				return kmsTest.HttpKMSSDK.VerifySignature(context.Background(), services.VerifySignInput{
					Identifier:  validKeyID,
					Message:     []byte{},
					Algorithm:   validAlgorithm,
					MessageType: models.Raw,
					Signature:   validSignature,
				})
			},
			resultCheck: func(ok *models.MessageValidation, err error) error {
				if err != nil {
					return fmt.Errorf("should not error on VerifySignature: %s", err)
				}
				if ok.Valid == true {
					return fmt.Errorf("expected false validation for empty message, got true")
				}
				return nil
			},
		},
		{
			name: "Error/VerifySignature-InvalidSignature",
			before: func() {
				validMessage = []byte("msg for invalid sig")
				validKeyID, validAlgorithm, _, _ = importAndSign("VerifyKey3", 2048, "RSASSA_PKCS1_V1_5_SHA_512", validMessage)
			},
			run: func() (*models.MessageValidation, error) {
				return kmsTest.HttpKMSSDK.VerifySignature(context.Background(), services.VerifySignInput{
					Identifier:  validKeyID,
					Message:     validMessage,
					Algorithm:   validAlgorithm,
					MessageType: models.Raw,
					Signature:   []byte("not a real signature"),
				})
			},
			resultCheck: func(ok *models.MessageValidation, err error) error {
				if err != nil {
					return fmt.Errorf("should not error on VerifySignature: %s", err)
				}
				if ok.Valid == true {
					return fmt.Errorf("expected false validation for invalid signature, got true")
				}
				return nil
			},
		},
		{
			name: "Error/VerifySignature-AlgorithmMismatch",
			before: func() {
				validMessage = []byte("algo mismatch msg")
				validKeyID, validAlgorithm, _, validSignature = importAndSign("VerifyKey4", 2048, "RSASSA_PKCS1_V1_5_SHA_512", validMessage)
			},
			run: func() (*models.MessageValidation, error) {
				return kmsTest.HttpKMSSDK.VerifySignature(context.Background(), services.VerifySignInput{
					Identifier:  validKeyID,
					Message:     validMessage,
					Algorithm:   "RSASSA_PKCS1_V1_5_SHA_256", // mismatch
					MessageType: models.Raw,
					Signature:   validSignature,
				})
			},
			resultCheck: func(ok *models.MessageValidation, err error) error {
				if err != nil {
					return fmt.Errorf("should not error on VerifySignature: %s", err)
				}
				if ok.Valid == true {
					return fmt.Errorf("expected false validation for algorithm mismatch, got true")
				}
				return nil
			},
		},
		{
			name: "Error/VerifySignature-HashType-InvalidHashLength",
			before: func() {
				validKeyID, validAlgorithm, _, validSignature = importAndSign("VerifyKey5", 2048, "RSASSA_PKCS1_V1_5_SHA_256", []byte("dummy message"))
			},
			run: func() (*models.MessageValidation, error) {
				// Using SHA-256 algorithm but providing incorrect hash length
				// SHA-256 expects 32 bytes, but we provide 20 bytes
				invalidHashMessage := make([]byte, 20) // Wrong length for SHA-256
				return kmsTest.HttpKMSSDK.VerifySignature(context.Background(), services.VerifySignInput{
					Identifier:  validKeyID,
					Message:     invalidHashMessage,
					Algorithm:   "RSASSA_PKCS1_V1_5_SHA_256", // SHA-256 expects 32 bytes
					MessageType: models.Hashed,               // This should trigger hash length validation
					Signature:   validSignature,
				})
			},
			resultCheck: func(ok *models.MessageValidation, err error) error {
				if err == nil {
					return fmt.Errorf("expected error for invalid hash length when MessageType is Hash in verification, got nil")
				}
				expectedErrMsg := "invalid digest size"
				if !strings.Contains(err.Error(), expectedErrMsg) {
					return fmt.Errorf("expected error to contain '%s', but got: %s", expectedErrMsg, err.Error())
				}
				return nil
			},
		},
		{
			name: "OK/VerifySignature-HashType-ValidHashLength",
			before: func() {
				// Create a key and sign a known hash for verification
				pem := func(bits int) any {
					priv, _ := rsa.GenerateKey(rand.Reader, 2048)
					return priv
				}(2048)
				key, err := kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
					Name:       "VerifyKey6",
					PrivateKey: pem,
					EngineID:   "filesystem-1",
				})
				if err != nil {
					panic(fmt.Sprintf("failed to import key for test: %s", err))
				}
				validKeyID = key.PKCS11URI
				validAlgorithm = "RSASSA_PKCS1_V1_5_SHA_256"
				// Create a valid SHA-256 hash (32 bytes)
				validHashMessage := make([]byte, 32)
				for i := range validHashMessage {
					validHashMessage[i] = byte(i % 256)
				}
				// Sign the hash to get a valid signature
				sig, err := kmsTest.HttpKMSSDK.SignMessage(context.Background(), services.SignMessageInput{
					Identifier:  validKeyID,
					Message:     validHashMessage,
					Algorithm:   validAlgorithm,
					MessageType: models.Hashed,
				})
				if err != nil {
					panic(fmt.Sprintf("failed to sign hash for test: %s", err))
				}

				validSignature = sig.Signature
				validMessage = validHashMessage
			},
			run: func() (*models.MessageValidation, error) {
				return kmsTest.HttpKMSSDK.VerifySignature(context.Background(), services.VerifySignInput{
					Identifier:  validKeyID,
					Message:     validMessage,
					Algorithm:   "RSASSA_PKCS1_V1_5_SHA_256", // SHA-256 expects 32 bytes
					MessageType: models.Hashed,               // This should pass hash length validation
					Signature:   validSignature,
				})
			},
			resultCheck: func(ok *models.MessageValidation, err error) error {
				if err != nil {
					return fmt.Errorf("should not error when providing correct hash length for MessageType Hash in verification: %s", err)
				}
				if !ok.Valid {
					return fmt.Errorf("expected successful verification with correct hash length, got false")
				}
				return nil
			},
		},
		{
			name: "Error/VerifySignature-ECDSA256-WrongHashSize",
			before: func() {
				// Create ECDSA-256 key and sign with correct hash
				pem := func() any {
					priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					return priv
				}()
				key, err := kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
					Name:       "VerifyECDSA256-WrongHash",
					PrivateKey: pem,
					EngineID:   "filesystem-1",
				})
				if err != nil {
					panic(fmt.Sprintf("failed to import ECDSA-256 key for verification: %s", err))
				}
				validKeyID = key.PKCS11URI
				// Sign with correct hash to get a valid signature
				correctHashMessage := make([]byte, 32) // Correct for SHA-256
				for i := range correctHashMessage {
					correctHashMessage[i] = byte(i % 256)
				}
				sig, err := kmsTest.HttpKMSSDK.SignMessage(context.Background(), services.SignMessageInput{
					Identifier:  validKeyID,
					Message:     correctHashMessage,
					Algorithm:   "ECDSA_SHA_256",
					MessageType: models.Hashed,
				})
				if err != nil {
					panic(fmt.Sprintf("failed to sign hash for ECDSA verification test: %s", err))
				}

				validSignature = sig.Signature
			},
			run: func() (*models.MessageValidation, error) {
				// Try to verify with wrong hash size (48 bytes instead of 32)
				wrongHashMessage := make([]byte, 48) // Wrong length for ECDSA_SHA_256
				return kmsTest.HttpKMSSDK.VerifySignature(context.Background(), services.VerifySignInput{
					Identifier:  validKeyID,
					Message:     wrongHashMessage,
					Algorithm:   "ECDSA_SHA_256", // SHA-256 expects 32 bytes, not 48
					MessageType: models.Hashed,
					Signature:   validSignature,
				})
			},
			resultCheck: func(ok *models.MessageValidation, err error) error {
				if err == nil {
					return fmt.Errorf("expected error for ECDSA-256 verification with wrong hash size, got nil")
				}
				expectedErrMsg := "invalid digest size"
				if !strings.Contains(err.Error(), expectedErrMsg) {
					return fmt.Errorf("expected error to contain '%s', but got: %s", expectedErrMsg, err.Error())
				}
				return nil
			},
		},
		{
			name: "OK/VerifySignature-ECDSA384-CorrectHashSize",
			before: func() {
				// Create ECDSA-384 key and sign with correct hash
				pem := func() any {
					priv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
					return priv
				}()
				key, err := kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
					Name:       "VerifyECDSA384-CorrectHash",
					PrivateKey: pem,
					EngineID:   "filesystem-1",
				})
				if err != nil {
					panic(fmt.Sprintf("failed to import ECDSA-384 key for verification: %s", err))
				}
				validKeyID = key.PKCS11URI
				// Sign with correct hash to get a valid signature
				correctHashMessage := make([]byte, 48) // Correct for SHA-384
				for i := range correctHashMessage {
					correctHashMessage[i] = byte(i % 256)
				}
				validMessage = correctHashMessage
				sig, err := kmsTest.HttpKMSSDK.SignMessage(context.Background(), services.SignMessageInput{
					Identifier:  validKeyID,
					Message:     correctHashMessage,
					Algorithm:   "ECDSA_SHA_384",
					MessageType: models.Hashed,
				})
				if err != nil {
					panic(fmt.Sprintf("failed to sign hash for ECDSA-384 verification test: %s", err))
				}
				validSignature = sig.Signature
			},
			run: func() (*models.MessageValidation, error) {
				return kmsTest.HttpKMSSDK.VerifySignature(context.Background(), services.VerifySignInput{
					Identifier:  validKeyID,
					Message:     validMessage,
					Algorithm:   "ECDSA_SHA_384", // SHA-384 expects 48 bytes
					MessageType: models.Hashed,
					Signature:   validSignature,
				})
			},
			resultCheck: func(ok *models.MessageValidation, err error) error {
				if err != nil {
					return fmt.Errorf("should not error for ECDSA-384 verification with correct hash size: %s", err)
				}
				if !ok.Valid {
					return fmt.Errorf("expected successful ECDSA-384 verification with correct hash length, got false")
				}
				return nil
			},
		},
		{
			name: "Error/VerifySignature-ECDSA521-WrongHashSize",
			before: func() {
				// Create ECDSA-521 key and sign with correct hash
				pem := func() any {
					priv, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
					return priv
				}()
				key, err := kmsTest.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{
					Name:       "VerifyECDSA521-WrongHash",
					PrivateKey: pem,
					EngineID:   "filesystem-1",
				})
				if err != nil {
					panic(fmt.Sprintf("failed to import ECDSA-521 key for verification: %s", err))
				}
				validKeyID = key.PKCS11URI
				// Sign with correct hash to get a valid signature
				correctHashMessage := make([]byte, 64) // Correct for SHA-512
				for i := range correctHashMessage {
					correctHashMessage[i] = byte(i % 256)
				}
				sig, err := kmsTest.HttpKMSSDK.SignMessage(context.Background(), services.SignMessageInput{
					Identifier:  validKeyID,
					Message:     correctHashMessage,
					Algorithm:   "ECDSA_SHA_512",
					MessageType: models.Hashed,
				})
				if err != nil {
					panic(fmt.Sprintf("failed to sign hash for ECDSA-521 verification test: %s", err))
				}
				validSignature = sig.Signature
			},
			run: func() (*models.MessageValidation, error) {
				// Try to verify with wrong hash size (32 bytes instead of 64)
				wrongHashMessage := make([]byte, 32) // Wrong length for ECDSA_SHA_512
				return kmsTest.HttpKMSSDK.VerifySignature(context.Background(), services.VerifySignInput{
					Identifier:  validKeyID,
					Message:     wrongHashMessage,
					Algorithm:   "ECDSA_SHA_512", // SHA-512 expects 64 bytes, not 32
					MessageType: models.Hashed,
					Signature:   validSignature,
				})
			},
			resultCheck: func(ok *models.MessageValidation, err error) error {
				if err == nil {
					return fmt.Errorf("expected error for ECDSA-521 verification with wrong hash size, got nil")
				}
				expectedErrMsg := "invalid digest size"
				if !strings.Contains(err.Error(), expectedErrMsg) {
					return fmt.Errorf("expected error to contain '%s', but got: %s", expectedErrMsg, err.Error())
				}
				return nil
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tc.before()
			ok, err := tc.run()
			err = tc.resultCheck(ok, err)
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

func parsePKCS11URI(uri string) (map[string]string, error) {
	result := make(map[string]string)

	// Strip the scheme ("pkcs11:") if present
	uri = strings.TrimPrefix(uri, "pkcs11:")

	// Split key=value pairs by ";"
	parts := strings.Split(uri, ";")
	for _, part := range parts {
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid part: %s", part)
		}
		key := kv[0]
		val := kv[1]
		result[key] = val
	}

	return result, nil
}
