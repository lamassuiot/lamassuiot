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
	"io"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/sirupsen/logrus"
)

var lAWSKMS *logrus.Entry

type AWSKMSCryptoEngine struct {
	config    models.CryptoEngineInfo
	kmscli    *kms.Client
	kmsConfig aws.Config
}

func NewAWSKMSEngine(logger *logrus.Entry, awsConf aws.Config, metadata map[string]any) (CryptoEngine, error) {
	lAWSKMS = logger.WithField("subsystem-provider", "AWS-KMS")

	httpCli, err := helpers.BuildHTTPClientWithTracerLogger(&http.Client{}, lAWSKMS)
	if err != nil {
		return nil, err
	}

	awsConf.HTTPClient = httpCli
	kmscli := kms.NewFromConfig(awsConf)

	return &AWSKMSCryptoEngine{
		kmscli:    kmscli,
		kmsConfig: awsConf,
		config: models.CryptoEngineInfo{
			Type:          models.AWSKMS,
			SecurityLevel: models.SL2,
			Provider:      "Amazon Web Services",
			Name:          "KMS",
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
						256,
						384,
						521,
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
	keys, err := p.kmscli.ListKeys(context.Background(), &kms.ListKeysInput{
		Limit: aws.Int32(100),
	})

	if err != nil {
		lAWSKMS.Errorf("could not get key list: %s", err)
		return nil, err
	}

	for _, key := range keys.Keys {
		aliases, err := p.kmscli.ListAliases(context.Background(), &kms.ListAliasesInput{
			KeyId: key.KeyId,
		})
		if err != nil {
			lAWSKMS.Errorf("could not get aliases list: %s", err)
			continue
		}

		for _, alias := range aliases.Aliases {
			aliasName := strings.Replace(*alias.AliasName, "alias/", "", -1)
			if aliasName == keyAlias {
				keyID = *key.KeyArn
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

	signer, err := newKmsKeyCryptoSingerWrapper(p.kmscli, keyID)

	return signer, err
}

func (p *AWSKMSCryptoEngine) CreateRSAPrivateKey(keySize int, keyID string) (crypto.Signer, error) {
	lAWSKMS.Debugf("Creating RSA key with ID: %s", keyID)

	var keySpec types.KeySpec

	switch keySize {
	case 2048:
		keySpec = types.KeySpecRsa2048
	case 3072:
		keySpec = types.KeySpecRsa3072
	case 4096:
		keySpec = types.KeySpecRsa4096
	default:
		err := fmt.Errorf("key curve not supported")
		lAWSKMS.Error(err)
		return nil, err
	}

	key, err := p.kmscli.CreateKey(context.Background(), &kms.CreateKeyInput{
		KeyUsage: types.KeyUsageTypeSignVerify,
		KeySpec:  keySpec,
	})

	if err != nil {
		lAWSKMS.Errorf("could not create '%s' RSA Private Key: %s", keyID, err)
		return nil, err
	}

	lAWSKMS.Debugf("RSA key created with ARN [%s]", *key.KeyMetadata.Arn)

	_, err = p.kmscli.CreateAlias(context.Background(), &kms.CreateAliasInput{
		AliasName:   aws.String(fmt.Sprintf("alias/%s", keyID)),
		TargetKeyId: key.KeyMetadata.Arn,
	})

	if err != nil {
		lAWSKMS.Warnf("Could not create alias for key ARN [%s]: %s", *key.KeyMetadata.Arn, err)
	}

	return p.GetPrivateKeyByID(keyID)
}

func (p *AWSKMSCryptoEngine) CreateECDSAPrivateKey(curve elliptic.Curve, keyID string) (crypto.Signer, error) {
	lAWSKMS.Debugf("Creating ECDSA key with ID: %s and curve %s", keyID, curve.Params().Name)

	var keySpec types.KeySpec

	switch curve.Params().Name {
	case "P-256":
		keySpec = types.KeySpecEccNistP256
	case "P-384":
		keySpec = types.KeySpecEccNistP384
	case "P-521":
		keySpec = types.KeySpecEccNistP521
	default:
		err := fmt.Errorf("key curve not supported")
		lAWSKMS.Error(err)
		return nil, err
	}

	key, err := p.kmscli.CreateKey(context.Background(), &kms.CreateKeyInput{
		KeyUsage: types.KeyUsageTypeSignVerify,
		KeySpec:  keySpec,
	})

	if err != nil {
		lAWSKMS.Errorf("could not create '%s' ECDSA Private Key: %s", keyID, err)
		return nil, err
	}

	lAWSKMS.Debugf("ECDSA key created with ARN [%s]", *key.KeyMetadata.Arn)

	_, err = p.kmscli.CreateAlias(context.Background(), &kms.CreateAliasInput{
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

type kmsKeyCryptoSingerWrapper struct {
	keyArn string
	sdk    *kms.Client

	publicKey crypto.PublicKey
}

func newKmsKeyCryptoSingerWrapper(sdk *kms.Client, keyArn string) (crypto.Signer, error) {
	//preload PubKey from KMS
	pubResp, err := sdk.GetPublicKey(context.TODO(), &kms.GetPublicKeyInput{
		KeyId: &keyArn,
	})
	if err != nil {
		return nil, err
	}

	pubKey, err := x509.ParsePKIXPublicKey(pubResp.PublicKey)
	if err != nil {
		return nil, err
	}

	return &kmsKeyCryptoSingerWrapper{
		sdk:       sdk,
		keyArn:    keyArn,
		publicKey: pubKey,
	}, nil
}

func (k *kmsKeyCryptoSingerWrapper) Public() crypto.PublicKey {
	return k.publicKey
}
func (k *kmsKeyCryptoSingerWrapper) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	alg, err := getSigningAlgorithm(k.Public(), opts)
	if err != nil {
		return nil, err
	}

	req := &kms.SignInput{
		KeyId:            &k.keyArn,
		SigningAlgorithm: alg,
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
	}

	resp, err := k.sdk.Sign(context.TODO(), req)
	if err != nil {
		return nil, err
	}

	return resp.Signature, nil

}

func getSigningAlgorithm(key crypto.PublicKey, opts crypto.SignerOpts) (types.SigningAlgorithmSpec, error) {
	switch key.(type) {
	case *rsa.PublicKey:
		_, isPSS := opts.(*rsa.PSSOptions)
		switch h := opts.HashFunc(); h {
		case crypto.SHA256:
			if isPSS {
				return types.SigningAlgorithmSpecRsassaPssSha256, nil
			}
			return types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, nil
		case crypto.SHA384:
			if isPSS {
				return types.SigningAlgorithmSpecRsassaPssSha384, nil
			}
			return types.SigningAlgorithmSpecRsassaPkcs1V15Sha384, nil
		case crypto.SHA512:
			if isPSS {
				return types.SigningAlgorithmSpecRsassaPssSha512, nil
			}
			return types.SigningAlgorithmSpecRsassaPkcs1V15Sha512, nil
		default:
			return "", fmt.Errorf("unsupported hash function %v", h)
		}
	case *ecdsa.PublicKey:
		switch h := opts.HashFunc(); h {
		case crypto.SHA256:
			return types.SigningAlgorithmSpecEcdsaSha256, nil
		case crypto.SHA384:
			return types.SigningAlgorithmSpecEcdsaSha384, nil
		case crypto.SHA512:
			return types.SigningAlgorithmSpecEcdsaSha512, nil
		default:
			return "", fmt.Errorf("unsupported hash function %v", h)
		}
	default:
		return "", fmt.Errorf("unsupported key type %T", key)
	}
}
