package aws

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/sirupsen/logrus"
)

var lAWSSM *logrus.Entry

type AWSSecretsManagerCryptoEngine struct {
	config    models.CryptoEngineInfo
	smngerCli *secretsmanager.Client
}

func NewAWSSecretManagerEngine(logger *logrus.Entry, awsConf aws.Config, metadata map[string]any) (cryptoengines.CryptoEngine, error) {
	lAWSSM = logger.WithField("subsystem-provider", "AWS SecretsManager Client")

	httpCli, err := helpers.BuildHTTPClientWithTracerLogger(http.DefaultClient, lAWSSM)
	if err != nil {
		return nil, err
	}

	awsConf.HTTPClient = httpCli

	smCli := secretsmanager.NewFromConfig(awsConf)

	return &AWSSecretsManagerCryptoEngine{
		smngerCli: smCli,
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

func (engine *AWSSecretsManagerCryptoEngine) GetPrivateKeyByID(keyID string) (crypto.Signer, error) {
	lAWSSM.Debugf("Getting the private key with ID: %s", keyID)

	result, err := engine.smngerCli.GetSecretValue(context.Background(), &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(keyID),
	})
	if err != nil {
		lAWSSM.Errorf("could not get Secret Value: %s", err)
		return nil, err
	}

	// Decrypts secret using the associated KMS key.
	var secretString string = *result.SecretString
	var keyMap map[string]string

	err = json.Unmarshal([]byte(secretString), &keyMap)
	if err != nil {
		return nil, err
	}

	b64Key, ok := keyMap["key"]
	if !ok {
		lAWSSM.Errorf("'key' variable not found in secret")
		return nil, fmt.Errorf("'key' not found in secret")
	}

	pemBytes, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no key found")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type %q", block.Type)
	}

}

func (engine *AWSSecretsManagerCryptoEngine) CreateRSAPrivateKey(keySize int, keyID string) (crypto.Signer, error) {
	lAWSSM.Debugf("Creating RSA key with ID %s", keyID)
	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		lAWSSM.Error("Could not create RSA private key: ", err)
		return nil, err
	}

	return engine.ImportRSAPrivateKey(key, keyID)
}

func (engine *AWSSecretsManagerCryptoEngine) CreateECDSAPrivateKey(curve elliptic.Curve, keyID string) (crypto.Signer, error) {
	lAWSSM.Debugf("Creating ECDSA key with ID %s", keyID)
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		lAWSSM.Error("Could not create ECDSA private key: ", err)
		return nil, err
	}

	return engine.ImportECDSAPrivateKey(key, keyID)
}

func (engine *AWSSecretsManagerCryptoEngine) ImportRSAPrivateKey(key *rsa.PrivateKey, keyID string) (crypto.Signer, error) {
	lAWSSM.Debugf("Import RSA key with ID: %s", keyID)
	keyBytes := pem.EncodeToMemory(&pem.Block{
		Bytes: x509.MarshalPKCS1PrivateKey(key),
		Type:  "RSA PRIVATE KEY",
	})

	b64Key := base64.StdEncoding.EncodeToString(keyBytes)
	keyVal := `{"key": "` + b64Key + `"}`

	_, err := engine.smngerCli.CreateSecret(context.Background(), &secretsmanager.CreateSecretInput{
		Name:         aws.String(keyID),
		SecretString: aws.String(keyVal),
	})

	if err != nil {
		lAWSSM.Error("Could not import RSA private key: ", err)
		return nil, err
	}

	return key, nil
}

func (engine *AWSSecretsManagerCryptoEngine) ImportECDSAPrivateKey(key *ecdsa.PrivateKey, keyID string) (crypto.Signer, error) {
	lAWSSM.Debugf("Import ECDSA key with ID: %s", keyID)
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}

	keyBytes = pem.EncodeToMemory(&pem.Block{
		Bytes: keyBytes,
		Type:  "EC PRIVATE KEY",
	})

	b64Key := base64.StdEncoding.EncodeToString(keyBytes)
	keyVal := `{"key": "` + b64Key + `"}`

	_, err = engine.smngerCli.CreateSecret(context.Background(), &secretsmanager.CreateSecretInput{
		Name:         &keyID,
		SecretString: aws.String(keyVal),
	})

	if err != nil {
		lAWSSM.Error("Could not import ECDSA private key: ", err)
		return nil, err
	}

	return key, nil
}

func (engine *AWSSecretsManagerCryptoEngine) DeleteKey(keyID string) error {
	return fmt.Errorf("cannot delete key [%s]. Go to your aws account and do it manually", keyID)
}
