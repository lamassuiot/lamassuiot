package aws

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
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/engines/crypto/software/v3"
	chelpers "github.com/lamassuiot/lamassuiot/shared/http/v3/pkg/helpers"
	"github.com/sirupsen/logrus"
)

var lAWSKMS *logrus.Entry

type AWSKMSCryptoEngine struct {
	softCryptoEngine *software.SoftwareCryptoEngine
	config           models.CryptoEngineInfo
	kmscli           *kms.Client
	kmsConfig        aws.Config
}

func NewAWSKMSEngine(logger *logrus.Entry, awsConf aws.Config, metadata map[string]any) (cryptoengines.CryptoEngine, error) {
	lAWSKMS = logger.WithField("subsystem-provider", "AWS-KMS")

	httpCli, err := chelpers.BuildHTTPClientWithTracerLogger(&http.Client{}, lAWSKMS)
	if err != nil {
		return nil, err
	}

	awsConf.HTTPClient = httpCli
	kmscli := kms.NewFromConfig(awsConf)

	return &AWSKMSCryptoEngine{
		kmscli:           kmscli,
		kmsConfig:        awsConf,
		softCryptoEngine: software.NewSoftwareCryptoEngine(lAWSKMS),
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

func (p *AWSKMSCryptoEngine) ListPrivateKeyIDs() ([]string, error) {
	keys, err := p.kmscli.ListKeys(context.Background(), &kms.ListKeysInput{
		Limit: aws.Int32(100),
	})

	if err != nil {
		lAWSKMS.Errorf("could not get key list: %s", err)
		return nil, err
	}

	var keyIDs []string
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
			keyIDs = append(keyIDs, aliasName)
		}
	}

	return keyIDs, nil
}

func (p *AWSKMSCryptoEngine) CreateRSAPrivateKey(keySize int) (string, crypto.Signer, error) {
	lAWSKMS.Debugf("Creating RSA key with size %d", keySize)

	var keySpec types.KeySpec

	switch keySize {
	case 2048:
		keySpec = types.KeySpecRsa2048
	case 3072:
		keySpec = types.KeySpecRsa3072
	case 4096:
		keySpec = types.KeySpecRsa4096
	default:
		err := fmt.Errorf("key size not supported")
		lAWSKMS.Error(err)
		return "", nil, err
	}

	return p.createPrivateKey(keySpec)
}

func (p *AWSKMSCryptoEngine) CreateECDSAPrivateKey(curve elliptic.Curve) (string, crypto.Signer, error) {
	lAWSKMS.Debugf("Creating ECDSA key with curve %s", curve.Params().Name)

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
		return "", nil, err
	}

	return p.createPrivateKey(keySpec)
}

func (p *AWSKMSCryptoEngine) createPrivateKey(keySpec types.KeySpec) (string, crypto.Signer, error) {
	key, err := p.kmscli.CreateKey(context.Background(), &kms.CreateKeyInput{
		KeyUsage: types.KeyUsageTypeSignVerify,
		KeySpec:  keySpec,
	})

	if err != nil {
		lAWSKMS.Errorf("could not create private key: %s", err)
		return "", nil, err
	}

	signer, err := newKmsKeyCryptoSingerWrapper(p.kmscli, *key.KeyMetadata.Arn)
	if err != nil {
		lAWSKMS.Errorf("could not create private key: %s", err)
		return "", nil, err
	}

	lAWSKMS.Debugf("Key created with ARN [%s]", *key.KeyMetadata.Arn)
	keyID, err := p.softCryptoEngine.EncodePKIXPublicKeyDigest(signer.Public())
	if err != nil {
		lAWSKMS.Errorf("could not encode public key digest: %s", err)
		return "", nil, err
	}

	_, err = p.kmscli.CreateAlias(context.Background(), &kms.CreateAliasInput{
		AliasName:   aws.String(fmt.Sprintf("alias/%s", keyID)),
		TargetKeyId: key.KeyMetadata.Arn,
	})

	if err != nil {
		lAWSKMS.Warnf("Could not create alias for key ARN [%s]: %s", *key.KeyMetadata.Arn, err)
	}

	return keyID, signer, nil
}

func (p *AWSKMSCryptoEngine) ImportRSAPrivateKey(key *rsa.PrivateKey) (string, crypto.Signer, error) {
	lAWSKMS.Warnf("KMS does not support asymmetric key import. See https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html")
	return "", nil, fmt.Errorf("KMS does not support asymmetric key import")
}

func (p *AWSKMSCryptoEngine) ImportECDSAPrivateKey(key *ecdsa.PrivateKey) (string, crypto.Signer, error) {
	lAWSKMS.Warnf("KMS does not support asymmetric key import. See https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html")
	return "", nil, fmt.Errorf("KMS does not support asymmetric key import")
}

func (p *AWSKMSCryptoEngine) RenameKey(oldID, newID string) error {
	desc, err := p.kmscli.DescribeKey(context.Background(), &kms.DescribeKeyInput{
		KeyId: aws.String(fmt.Sprintf("alias/%s", oldID)),
	})
	if err != nil {
		lAWSKMS.Errorf("could not get key description: %s", err)
		return err
	}

	_, err = p.kmscli.CreateAlias(context.Background(), &kms.CreateAliasInput{
		AliasName:   aws.String(fmt.Sprintf("alias/%s", newID)),
		TargetKeyId: desc.KeyMetadata.Arn,
	})
	if err != nil {
		lAWSKMS.Errorf("could not create key: %s", err)
		return err
	}

	_, err = p.kmscli.DeleteAlias(context.Background(), &kms.DeleteAliasInput{
		AliasName: aws.String(fmt.Sprintf("alias/%s", oldID)),
	})
	if err != nil {
		lAWSKMS.Errorf("could not delete key: %s", err)
	}

	return nil
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
