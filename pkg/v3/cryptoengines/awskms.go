package cryptoengines

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/sirupsen/logrus"

	"github.com/lstoll/awskms"
)

var lAWSKMS *logrus.Entry

type AWSKMSCryptoEngine struct {
	config models.CryptoEngineInfo
	kmscli *kms.KMS
}

func NewAWSKMSEngine(logger *logrus.Entry, conf config.AWSSDKConfig) (CryptoEngine, error) {
	lAWSKMS = logger.WithField("subsystem-provider", "AWS-KMS")

	httpCli, err := helpers.BuildHTTPClientWithTracerLogger(&http.Client{}, lAWSKMS)
	if err != nil {
		return nil, err
	}

	sess := session.Must(session.NewSession(&aws.Config{
		Region:      aws.String(conf.Region),
		Credentials: credentials.NewStaticCredentials(conf.AccessKeyID, string(conf.SecretAccessKey), ""),
		HTTPClient:  httpCli,
	}))
	kmscli := kms.New(sess)

	return &AWSKMSCryptoEngine{
		kmscli: kmscli,
		config: models.CryptoEngineInfo{
			Type:          models.AWSKMS,
			SecurityLevel: models.SL2,
			Provider:      "Amazon Web Services",
			Name:          "KMS",
			Metadata:      conf.Metadata,
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
						512,
					},
				},
			},
		},
	}, nil
}

func (p *AWSKMSCryptoEngine) GetEngineConfig() models.CryptoEngineInfo {
	return p.config
}

func (p *AWSKMSCryptoEngine) GetPrivateKeyByID(keyAlias string) (crypto.Signer, error) {
	lAWSKMS.Debugf("Getting the private key with Alias: %s", keyAlias)
	var keyID = ""
	keys, err := p.kmscli.ListKeys(&kms.ListKeysInput{
		Limit: aws.Int64(100),
	})

	if err != nil {
		lAWSKMS.Errorf("could not get key list: %s", err)
		return nil, err
	}

	for _, key := range keys.Keys {
		aliases, err := p.kmscli.ListAliases(&kms.ListAliasesInput{
			KeyId: key.KeyId,
		})
		if err != nil {
			lAWSKMS.Errorf("could not get aliases list: %s", err)
			continue
		}

		for _, alias := range aliases.Aliases {
			aliasName := strings.Replace(*alias.AliasName, "alias/", "", -1)
			if aliasName == keyAlias {
				keyID = *key.KeyId
				break
			}
		}

		if keyID == keyAlias {
			break
		}
	}

	if keyID == "" {
		lAWSKMS.Errorf("kms key not found")
		return nil, errors.New("kms key not found")
	}

	return awskms.NewSigner(context.Background(), p.kmscli, keyID)
}

func (p *AWSKMSCryptoEngine) CreateRSAPrivateKey(keySize int, keyID string) (crypto.Signer, error) {
	lAWSKMS.Debugf("Creating RSA key with ID: %s", keyID)
	key, err := p.kmscli.CreateKey(&kms.CreateKeyInput{
		KeyUsage: aws.String("SIGN_VERIFY"),
		KeySpec:  aws.String(fmt.Sprintf("RSA_%d", keySize)),
	})

	if err != nil {
		lAWSKMS.Errorf("could not create '%s' RSA Private Key: %s", keyID, err)
		return nil, err
	}

	lAWSKMS.Debugf("RSA key created with ARN [%s]", *key.KeyMetadata.Arn)

	_, err = p.kmscli.CreateAlias(&kms.CreateAliasInput{
		AliasName:   aws.String(fmt.Sprintf("alias/%s", keyID)),
		TargetKeyId: key.KeyMetadata.Arn,
	})

	if err != nil {
		lAWSKMS.Warnf("Could not create alias for key ARN [%s]: %s", *key.KeyMetadata.Arn, err)
	}

	return p.GetPrivateKeyByID(keyID)
}

func (p *AWSKMSCryptoEngine) CreateECDSAPrivateKey(curve elliptic.Curve, keyID string) (crypto.Signer, error) {
	lAWSKMS.Debugf("Creating ECDSA key with ID: %s", keyID)
	key, err := p.kmscli.CreateKey(&kms.CreateKeyInput{
		KeyUsage: aws.String("SIGN_VERIFY"),
		KeySpec:  aws.String(fmt.Sprintf("ECC_NIST_P%d", curve.Params().BitSize)),
	})

	if err != nil {
		lAWSKMS.Errorf("could not create '%s' ECDSA Private Key: %s", keyID, err)
		return nil, err
	}

	lAWSKMS.Debugf("ECDSA key created with ARN [%s]", *key.KeyMetadata.Arn)

	_, err = p.kmscli.CreateAlias(&kms.CreateAliasInput{
		AliasName:   aws.String(fmt.Sprintf("alias/%s", keyID)),
		TargetKeyId: key.KeyMetadata.Arn,
	})

	if err != nil {
		lAWSKMS.Warnf("Could not create alias for key ARN [%s]: %s", *key.KeyMetadata.Arn, err)
	}

	return p.GetPrivateKeyByID(keyID)
}

func (p *AWSKMSCryptoEngine) ImportRSAPrivateKey(key *rsa.PrivateKey, keyID string) (crypto.Signer, error) {
	lAWSKMS.Warnf("KMS does not support asymmetric key import. See https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html")
	return nil, fmt.Errorf("KMS does not support asymmetric key import")
}

func (p *AWSKMSCryptoEngine) ImportECDSAPrivateKey(key *ecdsa.PrivateKey, keyID string) (crypto.Signer, error) {
	lAWSKMS.Warnf("KMS does not support asymmetric key import. See https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html")
	return nil, fmt.Errorf("KMS does not support asymmetric key import")
}

func (p *AWSKMSCryptoEngine) DeleteKey(keyID string) error {
	return fmt.Errorf("cannot delete key [%s]. Go to your aws account and do it manually", keyID)
}
