package azure

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	software "github.com/lamassuiot/lamassuiot/engines/crypto/software/v3"
	lazure "github.com/lamassuiot/lamassuiot/shared/azure/v3"
	"github.com/sirupsen/logrus"
)

type AzureKeyVaultSecretsCryptoEngine struct {
	softCryptoEngine *software.SoftwareCryptoEngine
	config           models.CryptoEngineInfo
	secretsCli       *azsecrets.Client
	logger           *logrus.Entry
}

// NewAzureKeyVaultSecretsEngine creates a CryptoEngine backed by Azure Key Vault
// Secrets. Private keys are generated locally by the software engine and stored
// as base64-encoded PEM values inside Key Vault secrets. This mirrors the AWS
// Secrets Manager engine: SL1 security, full key algorithm support, and a
// RenameKey implementation that copies then deletes.
//
// When allowHTTP is true (e.g. for local emulators) the client is configured
// with a nil credential and an EmulatorAuthPolicy that injects a static bearer
// token, bypassing the Key Vault challenge policy's HTTP restriction.
func NewAzureKeyVaultSecretsEngine(logger *logrus.Entry, vaultURL string, credential azcore.TokenCredential, allowHTTP bool, metadata map[string]any) (cryptoengines.CryptoEngine, error) {
	lAzureSM := logger.WithField("subsystem-provider", "Azure Key Vault Secrets Client")

	clientOpts := &azsecrets.ClientOptions{}

	effectiveCred := credential
	if allowHTTP {
		effectiveCred = nil
		clientOpts.PerCallPolicies = []policy.Policy{&lazure.EmulatorAuthPolicy{}}
	}

	client, err := azsecrets.NewClient(vaultURL, effectiveCred, clientOpts)
	if err != nil {
		return nil, fmt.Errorf("creating Key Vault Secrets client: %w", err)
	}

	return &AzureKeyVaultSecretsCryptoEngine{
		logger:           lAzureSM,
		softCryptoEngine: software.NewSoftwareCryptoEngine(lAzureSM),
		secretsCli:       client,
		config: models.CryptoEngineInfo{
			Type:          models.AzureKeyVaultSecrets,
			SecurityLevel: models.SL1,
			Provider:      "Microsoft Azure",
			Name:          "Key Vault Secrets",
			Metadata:      metadata,
			SupportedKeyTypes: []models.SupportedKeyTypeInfo{
				{
					Type:  models.KeyType(x509.RSA),
					Sizes: []int{1024, 2048, 3072, 4096},
				},
				{
					Type:  models.KeyType(x509.ECDSA),
					Sizes: []int{224, 256, 384, 521},
				},
			},
		},
	}, nil
}

func (engine *AzureKeyVaultSecretsCryptoEngine) GetEngineConfig() models.CryptoEngineInfo {
	return engine.config
}

func (engine *AzureKeyVaultSecretsCryptoEngine) GetPrivateKeyByID(keyID string) (crypto.Signer, error) {
	engine.logger.Debugf("Getting the private key with ID: %s", keyID)

	result, err := engine.secretsCli.GetSecret(context.Background(), keyID, "", nil)
	if err != nil {
		engine.logger.Errorf("could not get secret %s: %s", keyID, err)
		return nil, err
	}

	if result.Value == nil {
		return nil, fmt.Errorf("secret %s has no value", keyID)
	}

	var keyMap map[string]string
	if err = json.Unmarshal([]byte(*result.Value), &keyMap); err != nil {
		return nil, fmt.Errorf("unmarshalling secret %s: %w", keyID, err)
	}

	pemB64, ok := keyMap["key"]
	if !ok {
		return nil, fmt.Errorf("'key' field not found in secret %s", keyID)
	}

	pemBytes, err := base64.StdEncoding.DecodeString(pemB64)
	if err != nil {
		return nil, fmt.Errorf("decoding key from secret %s: %w", keyID, err)
	}

	return engine.softCryptoEngine.ParsePrivateKey(pemBytes)
}

func (engine *AzureKeyVaultSecretsCryptoEngine) ListPrivateKeyIDs() ([]string, error) {
	engine.logger.Debugf("listing private key IDs")

	var keyIDs []string
	pager := engine.secretsCli.NewListSecretPropertiesPager(nil)
	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			return nil, fmt.Errorf("listing secrets: %w", err)
		}
		for _, sp := range page.Value {
			if sp.ID != nil {
				keyIDs = append(keyIDs, sp.ID.Name())
			}
		}
	}

	engine.logger.Debugf("private key IDs successfully listed")
	return keyIDs, nil
}

func (engine *AzureKeyVaultSecretsCryptoEngine) CreateRSAPrivateKey(ctx context.Context, keySize int) (string, crypto.Signer, error) {
	engine.logger.Debugf("creating RSA private key with size %d", keySize)

	_, key, err := engine.softCryptoEngine.CreateRSAPrivateKey(ctx, keySize)
	if err != nil {
		engine.logger.Errorf("could not create RSA private key: %s", err)
		return "", nil, err
	}

	return engine.importKey(key)
}

func (engine *AzureKeyVaultSecretsCryptoEngine) CreateECDSAPrivateKey(ctx context.Context, curve elliptic.Curve) (string, crypto.Signer, error) {
	engine.logger.Debugf("creating ECDSA private key with curve %s", curve.Params().Name)

	_, key, err := engine.softCryptoEngine.CreateECDSAPrivateKey(ctx, curve)
	if err != nil {
		engine.logger.Errorf("could not create ECDSA private key: %s", err)
		return "", nil, err
	}

	return engine.importKey(key)
}

func (engine *AzureKeyVaultSecretsCryptoEngine) ImportRSAPrivateKey(key *rsa.PrivateKey) (string, crypto.Signer, error) {
	engine.logger.Debugf("importing RSA private key")

	keyID, signer, err := engine.importKey(key)
	if err != nil {
		engine.logger.Errorf("could not import RSA key: %s", err)
		return "", nil, err
	}

	return keyID, signer, nil
}

func (engine *AzureKeyVaultSecretsCryptoEngine) ImportECDSAPrivateKey(key *ecdsa.PrivateKey) (string, crypto.Signer, error) {
	engine.logger.Debugf("importing ECDSA private key")

	keyID, signer, err := engine.importKey(key)
	if err != nil {
		engine.logger.Errorf("could not import ECDSA key: %s", err)
		return "", nil, err
	}

	return keyID, signer, nil
}

func (engine *AzureKeyVaultSecretsCryptoEngine) importKey(key crypto.Signer) (string, crypto.Signer, error) {
	keyID, err := engine.softCryptoEngine.EncodePKIXPublicKeyDigest(key.Public())
	if err != nil {
		engine.logger.Errorf("could not encode public key digest: %s", err)
		return "", nil, err
	}

	b64PemKey, err := engine.softCryptoEngine.MarshalAndEncodePKIXPrivateKey(key)
	if err != nil {
		engine.logger.Errorf("could not marshal and encode private key: %s", err)
		return "", nil, err
	}

	val := `{"key":"` + b64PemKey + `"}`
	_, err = engine.secretsCli.SetSecret(context.Background(), keyID, azsecrets.SetSecretParameters{
		Value: &val,
	}, nil)
	if err != nil {
		engine.logger.Errorf("could not store key in Key Vault Secrets: %s", err)
		return "", nil, fmt.Errorf("storing key in Key Vault Secrets: %w", err)
	}

	return keyID, key, nil
}

func (engine *AzureKeyVaultSecretsCryptoEngine) RenameKey(oldID, newID string) error {
	engine.logger.Debugf("renaming key %s -> %s", oldID, newID)

	result, err := engine.secretsCli.GetSecret(context.Background(), oldID, "", nil)
	if err != nil {
		engine.logger.Errorf("could not get secret %s: %s", oldID, err)
		return fmt.Errorf("getting secret %s: %w", oldID, err)
	}

	_, err = engine.secretsCli.SetSecret(context.Background(), newID, azsecrets.SetSecretParameters{
		Value: result.Value,
	}, nil)
	if err != nil {
		engine.logger.Errorf("could not create secret %s: %s", newID, err)
		return fmt.Errorf("creating secret %s: %w", newID, err)
	}

	engine.logger.Debugf("key successfully renamed")
	return engine.DeleteKey(oldID)
}

func (engine *AzureKeyVaultSecretsCryptoEngine) DeleteKey(keyID string) error {
	engine.logger.Debugf("deleting key with ID: %s", keyID)

	_, err := engine.secretsCli.DeleteSecret(context.Background(), keyID, nil)
	if err != nil {
		engine.logger.Errorf("could not delete secret %s: %s", keyID, err)
		return fmt.Errorf("deleting secret %s: %w", keyID, err)
	}

	engine.logger.Debugf("key successfully deleted")
	return nil
}
