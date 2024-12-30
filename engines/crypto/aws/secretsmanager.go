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
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
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
	engine.logger.Debugf("Getting the private key with ID: %s", keyID)

	result, err := engine.smngerCli.GetSecretValue(context.Background(), &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(keyID),
	})
	if err != nil {
		engine.logger.Errorf("could not get Secret Value: %s", err)
		return nil, err
	}

	// Decrypts secret using the associated KMS key.
	var secretString string = *result.SecretString
	var keyMap map[string]string

	err = json.Unmarshal([]byte(secretString), &keyMap)
	if err != nil {
		return nil, err
	}

	pemBytes, ok := keyMap["key"]
	if !ok {
		engine.logger.Errorf("'key' variable not found in secret")
		return nil, fmt.Errorf("'key' not found in secret")
	}

	decodedPemBytes, err := base64.StdEncoding.DecodeString(pemBytes)
	if err != nil {
		engine.logger.Errorf("could not decode key: %s", err)
		return nil, err
	}

	block, _ := pem.Decode([]byte(decodedPemBytes))
	if block == nil {
		engine.logger.Errorf("could not decode into PEM block")
		return nil, errors.New("could not decode into PEM block")
	}

	genericKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch genericKey.(type) {
	case *rsa.PrivateKey:
		return genericKey.(*rsa.PrivateKey), nil
	case *ecdsa.PrivateKey:
		return genericKey.(*ecdsa.PrivateKey), nil
	default:
		return nil, errors.New("unsupported key type")
	}
}

func (engine *AWSSecretsManagerCryptoEngine) CreateRSAPrivateKey(keySize int) (string, crypto.Signer, error) {
	engine.logger.Debugf("creating RSA private key")

	_, key, err := software.NewSoftwareCryptoEngine(engine.logger).CreateRSAPrivateKey(keySize)
	if err != nil {
		engine.logger.Errorf("could not create RSA private key: %s", err)
		return "", nil, err
	}

	engine.logger.Debugf("RSA key successfully generated")
	return engine.importKey(key)
}

func (engine *AWSSecretsManagerCryptoEngine) CreateECDSAPrivateKey(curve elliptic.Curve) (string, crypto.Signer, error) {
	engine.logger.Debugf("creating ECDSA private key")

	_, key, err := software.NewSoftwareCryptoEngine(engine.logger).CreateECDSAPrivateKey(curve)
	if err != nil {
		engine.logger.Errorf("could not create ECDSA private key: %s", err)
		return "", nil, err
	}

	engine.logger.Debugf("ECDSA key successfully generated")
	return engine.importKey(key)
}

func (engine *AWSSecretsManagerCryptoEngine) ImportRSAPrivateKey(key *rsa.PrivateKey) (string, crypto.Signer, error) {
	engine.logger.Debugf("importing RSA private key")

	keyID, signer, err := engine.importKey(key)
	if err != nil {
		engine.logger.Errorf("could not import RSA key: %s", err)
		return "", nil, err
	}

	engine.logger.Debugf("RSA key successfully imported")
	return keyID, signer, nil
}

func (engine *AWSSecretsManagerCryptoEngine) ImportECDSAPrivateKey(key *ecdsa.PrivateKey) (string, crypto.Signer, error) {
	engine.logger.Debugf("importing ECDSA private key")

	keyID, signer, err := engine.importKey(key)
	if err != nil {
		engine.logger.Errorf("could not import ECDSA key: %s", err)
		return "", nil, err
	}

	engine.logger.Debugf("ECDSA key successfully imported")
	return keyID, signer, nil
}

func (engine *AWSSecretsManagerCryptoEngine) importKey(key crypto.Signer) (string, crypto.Signer, error) {
	var pubKey any
	switch k := key.(type) {
	case *rsa.PrivateKey:
		pubKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		pubKey = &k.PublicKey
	default:
		return "", nil, errors.New("unsupported key type")
	}

	softEngine := software.NewSoftwareCryptoEngine(engine.logger)
	keyID, err := softEngine.EncodePKIXPublicKeyDigest(pubKey)
	if err != nil {
		engine.logger.Errorf("could not encode public key digest: %s", err)
		return "", nil, err
	}

	b64PemKey, err := softEngine.MarshalAndEncodePKIXPrivateKey(key)
	if err != nil {
		engine.logger.Errorf("could not marshal and encode private key: %s", err)
		return "", nil, err
	}

	keyVal := `{"key": "` + b64PemKey + `"}`

	_, err = engine.smngerCli.CreateSecret(context.Background(), &secretsmanager.CreateSecretInput{
		Name:         aws.String(keyID),
		SecretString: aws.String(keyVal),
	})

	if err != nil {
		engine.logger.Error("Could not import private key: ", err)
		return "", nil, err
	}

	return keyID, key, nil
}

func (engine *AWSSecretsManagerCryptoEngine) DeleteKey(keyID string) error {
	return fmt.Errorf("cannot delete key [%s]. Go to your aws account and do it manually", keyID)
}
