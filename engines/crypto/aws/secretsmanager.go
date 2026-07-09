package aws

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
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	corehelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/engines/crypto/software/v3"
	chelpers "github.com/lamassuiot/lamassuiot/shared/http/v3/pkg/helpers"
	"github.com/sirupsen/logrus"
)

type AWSSecretsManagerCryptoEngine struct {
	softCryptoEngine *software.SoftwareCryptoEngine
	config           models.CryptoEngineInfo
	smngerCli        *secretsmanager.Client
	logger           *logrus.Entry
}

func NewAWSSecretManagerEngine(logger *logrus.Entry, awsConf aws.Config, metadata map[string]any) (cryptoengines.CryptoEngine, error) {
	lAWSSM := logger.WithField("subsystem-provider", "AWS SecretsManager Client")

	httpCli, err := chelpers.BuildHTTPClientWithTracerLogger(http.DefaultClient, lAWSSM)
	if err != nil {
		return nil, err
	}

	awsConf.HTTPClient = httpCli

	smCli := secretsmanager.NewFromConfig(awsConf)

	return &AWSSecretsManagerCryptoEngine{
		logger:           lAWSSM,
		softCryptoEngine: software.NewSoftwareCryptoEngine(lAWSSM),
		smngerCli:        smCli,
		config: models.CryptoEngineInfo{
			Type:          models.AWSSecretsManager,
			SecurityLevel: models.SL1,
			Provider:      "Amazon Web Services",
			Name:          "Secrets Manager",
			Metadata:      metadata,
			SupportedKeyTypes: []models.SupportedKeyTypeInfo{
				{
					Type: models.KeyType(x509.RSA),
					Sizes: []int{
						1024,
						2048,
						3072,
						4096,
					},
				},
				{
					Type: models.KeyType(x509.ECDSA),
					Sizes: []int{
						224,
						256,
						384,
						521,
					},
				},
			},
		},
	}, nil
}

func (engine *AWSSecretsManagerCryptoEngine) GetEngineConfig() models.CryptoEngineInfo {
	return engine.config
}

func (engine *AWSSecretsManagerCryptoEngine) GetPrivateKeyByID(ctx context.Context, keyID string) (crypto.Signer, error) {
	lFunc := corehelpers.ConfigureLogger(ctx, engine.logger)
	lFunc.Debugf("Getting the private key with ID: %s", keyID)

	result, err := engine.smngerCli.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(keyID),
	})
	if err != nil {
		lFunc.Errorf("could not get Secret Value: %s", err)
		return nil, err
	}

	var secretString string = *result.SecretString
	var keyMap map[string]string

	err = json.Unmarshal([]byte(secretString), &keyMap)
	if err != nil {
		return nil, err
	}

	pemBytes, ok := keyMap["key"]
	if !ok {
		lFunc.Errorf("'key' variable not found in secret")
		return nil, fmt.Errorf("'key' not found in secret")
	}

	decodedPemBytes, err := base64.StdEncoding.DecodeString(pemBytes)
	if err != nil {
		lFunc.Errorf("could not decode key: %s", err)
		return nil, err
	}

	return engine.softCryptoEngine.ParsePrivateKey(decodedPemBytes)
}

func (engine *AWSSecretsManagerCryptoEngine) ListPrivateKeyIDs(ctx context.Context) ([]string, error) {
	lFunc := corehelpers.ConfigureLogger(ctx, engine.logger)
	lFunc.Debugf("listing private key IDs")

	keyRes, err := engine.smngerCli.ListSecrets(ctx, &secretsmanager.ListSecretsInput{})
	if err != nil {
		lFunc.Errorf("could not list secrets: %s", err)
		return nil, err
	}

	keys := []string{}
	for _, secret := range keyRes.SecretList {
		keys = append(keys, *secret.Name)
	}

	lFunc.Debugf("private key IDs successfully listed")

	return keys, nil
}

func (engine *AWSSecretsManagerCryptoEngine) CreateRSAPrivateKey(ctx context.Context, keySize int) (string, crypto.Signer, error) {
	lFunc := corehelpers.ConfigureLogger(ctx, engine.logger)
	lFunc.Debugf("creating RSA private key")

	_, key, err := engine.softCryptoEngine.CreateRSAPrivateKey(ctx, keySize)
	if err != nil {
		lFunc.Errorf("could not create RSA private key: %s", err)
		return "", nil, err
	}

	lFunc.Debugf("RSA key successfully generated")
	return engine.importKey(ctx, key)
}

func (engine *AWSSecretsManagerCryptoEngine) CreateECDSAPrivateKey(ctx context.Context, curve elliptic.Curve) (string, crypto.Signer, error) {
	lFunc := corehelpers.ConfigureLogger(ctx, engine.logger)
	lFunc.Debugf("creating ECDSA private key")

	_, key, err := engine.softCryptoEngine.CreateECDSAPrivateKey(ctx, curve)
	if err != nil {
		lFunc.Errorf("could not create ECDSA private key: %s", err)
		return "", nil, err
	}

	lFunc.Debugf("ECDSA key successfully generated")
	return engine.importKey(ctx, key)
}

func (engine *AWSSecretsManagerCryptoEngine) ImportRSAPrivateKey(ctx context.Context, key *rsa.PrivateKey) (string, crypto.Signer, error) {
	lFunc := corehelpers.ConfigureLogger(ctx, engine.logger)
	lFunc.Debugf("importing RSA private key")

	keyID, signer, err := engine.importKey(ctx, key)
	if err != nil {
		lFunc.Errorf("could not import RSA key: %s", err)
		return "", nil, err
	}

	lFunc.Debugf("RSA key successfully imported")
	return keyID, signer, nil
}

func (engine *AWSSecretsManagerCryptoEngine) ImportECDSAPrivateKey(ctx context.Context, key *ecdsa.PrivateKey) (string, crypto.Signer, error) {
	lFunc := corehelpers.ConfigureLogger(ctx, engine.logger)
	lFunc.Debugf("importing ECDSA private key")

	keyID, signer, err := engine.importKey(ctx, key)
	if err != nil {
		lFunc.Errorf("could not import ECDSA key: %s", err)
		return "", nil, err
	}

	lFunc.Debugf("ECDSA key successfully imported")
	return keyID, signer, nil
}

func (engine *AWSSecretsManagerCryptoEngine) importKey(ctx context.Context, key crypto.Signer) (string, crypto.Signer, error) {
	lFunc := corehelpers.ConfigureLogger(ctx, engine.logger)
	pubKey := key.Public()

	keyID, err := engine.softCryptoEngine.EncodePKIXPublicKeyDigest(ctx, pubKey)
	if err != nil {
		lFunc.Errorf("could not encode public key digest: %s", err)
		return "", nil, err
	}

	b64PemKey, err := engine.softCryptoEngine.MarshalAndEncodePKIXPrivateKey(ctx, key)
	if err != nil {
		lFunc.Errorf("could not marshal and encode private key: %s", err)
		return "", nil, err
	}

	keyVal := `{"key": "` + b64PemKey + `"}`

	_, err = engine.smngerCli.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
		Name:         aws.String(keyID),
		SecretString: aws.String(keyVal),
	})

	if err != nil {
		lFunc.Error("Could not import private key: ", err)
		return "", nil, err
	}

	return keyID, key, nil
}

func (engine *AWSSecretsManagerCryptoEngine) RenameKey(ctx context.Context, oldID, newID string) error {
	lFunc := corehelpers.ConfigureLogger(ctx, engine.logger)
	lFunc.Debugf("renaming key with ID: %s to %s", oldID, newID)

	result, err := engine.smngerCli.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(oldID),
	})
	if err != nil {
		lFunc.Errorf("could not get Secret Value: %s", err)
		return err
	}

	_, err = engine.smngerCli.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
		Name:         aws.String(newID),
		SecretString: result.SecretString,
	})
	if err != nil {
		lFunc.Errorf("could not create Secret Value: %s", err)
		return err
	}

	err = engine.DeleteKey(ctx, oldID)
	if err != nil {
		lFunc.Errorf("could not delete old key: %s", err)
	}

	lFunc.Debugf("key successfully renamed")
	return nil
}

func (engine *AWSSecretsManagerCryptoEngine) DeleteKey(ctx context.Context, keyID string) error {
	lFunc := corehelpers.ConfigureLogger(ctx, engine.logger)
	lFunc.Debugf("deleting key with ID: %s", keyID)

	_, err := engine.smngerCli.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{
		SecretId:             aws.String(keyID),
		RecoveryWindowInDays: aws.Int64(7),
	})

	if err != nil {
		lFunc.Errorf("could not delete key: %s", err)
		return err
	}

	lFunc.Debugf("key successfully deleted")
	return nil
}
