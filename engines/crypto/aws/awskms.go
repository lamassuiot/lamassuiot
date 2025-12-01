package aws

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
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

const aliasFormat = "alias/%s"

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

// getAllKMSKeys retrieves all KMS keys with pagination support
func (p *AWSKMSCryptoEngine) getAllKMSKeys(ctx context.Context) ([]types.KeyListEntry, error) {
	var allKeys []types.KeyListEntry
	var marker *string

	for {
		output, err := p.kmscli.ListKeys(ctx, &kms.ListKeysInput{
			Limit:  aws.Int32(100),
			Marker: marker,
		})
		if err != nil {
			return nil, err
		}

		allKeys = append(allKeys, output.Keys...)

		if output.NextMarker == nil || *output.NextMarker == "" {
			break
		}
		marker = output.NextMarker
	}

	return allKeys, nil
}

// getAliasesForKey retrieves all aliases for a specific key with pagination support
func (p *AWSKMSCryptoEngine) getAliasesForKey(ctx context.Context, keyID *string) ([]types.AliasListEntry, error) {
	var allAliases []types.AliasListEntry
	var marker *string

	for {
		output, err := p.kmscli.ListAliases(ctx, &kms.ListAliasesInput{
			KeyId:  keyID,
			Limit:  aws.Int32(100),
			Marker: marker,
		})
		if err != nil {
			return nil, err
		}

		allAliases = append(allAliases, output.Aliases...)

		if output.NextMarker == nil || *output.NextMarker == "" {
			break
		}
		marker = output.NextMarker
	}

	return allAliases, nil
}

// findKeyArnByAlias searches for a key ARN matching the given alias name
func (p *AWSKMSCryptoEngine) findKeyArnByAlias(ctx context.Context, keyAlias string) (string, error) {
	keys, err := p.getAllKMSKeys(ctx)
	if err != nil {
		lAWSKMS.Errorf("could not get key list: %s", err)
		return "", err
	}

	for _, key := range keys {
		aliases, err := p.getAliasesForKey(ctx, key.KeyId)
		if err != nil {
			lAWSKMS.Errorf("could not get aliases list for key %s: %s", *key.KeyId, err)
			continue
		}

		for _, alias := range aliases {
			aliasName := strings.ReplaceAll(*alias.AliasName, "alias/", "")
			if aliasName == keyAlias {
				return *key.KeyArn, nil
			}
		}
	}

	return "", errors.New("kms key not found")
}

func (p *AWSKMSCryptoEngine) GetPrivateKeyByID(keyAlias string) (crypto.Signer, error) {
	lAWSKMS.Debugf("Getting the private key with Alias: %s", keyAlias)

	keyArn, err := p.findKeyArnByAlias(context.Background(), keyAlias)
	if err != nil {
		lAWSKMS.Errorf("kms key not found")
		return nil, err
	}

	signer, err := newKmsKeyCryptoSignerWrapper(p.kmscli, keyArn)
	return signer, err
}

// collectUserAliasNames extracts user-managed alias names (excluding AWS-managed aliases)
func (p *AWSKMSCryptoEngine) collectUserAliasNames(aliases []types.AliasListEntry) []string {
	var aliasNames []string
	for _, alias := range aliases {
		if strings.HasPrefix(*alias.AliasName, "alias/aws/") {
			continue
		}
		aliasName := strings.ReplaceAll(*alias.AliasName, "alias/", "")
		aliasNames = append(aliasNames, aliasName)
	}
	return aliasNames
}

func (p *AWSKMSCryptoEngine) ListPrivateKeyIDs() ([]string, error) {
	var keyIDs []string

	keys, err := p.getAllKMSKeys(context.Background())
	if err != nil {
		lAWSKMS.Errorf("could not get key list: %s", err)
		return nil, err
	}

	for _, key := range keys {
		aliases, err := p.getAliasesForKey(context.Background(), key.KeyId)
		if err != nil {
			lAWSKMS.Errorf("could not get aliases list for key %s: %s", *key.KeyId, err)
			continue
		}

		userAliases := p.collectUserAliasNames(aliases)
		keyIDs = append(keyIDs, userAliases...)
	}

	return keyIDs, nil
}

func (p *AWSKMSCryptoEngine) CreateRSAPrivateKey(ctx context.Context, keySize int) (string, crypto.Signer, error) {
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

	return p.createPrivateKey(ctx, keySpec)
}

func (p *AWSKMSCryptoEngine) CreateECDSAPrivateKey(ctx context.Context, curve elliptic.Curve) (string, crypto.Signer, error) {
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

	return p.createPrivateKey(ctx, keySpec)
}

func (p *AWSKMSCryptoEngine) createPrivateKey(ctx context.Context, keySpec types.KeySpec) (string, crypto.Signer, error) {
	key, err := p.kmscli.CreateKey(ctx, &kms.CreateKeyInput{
		KeyUsage: types.KeyUsageTypeSignVerify,
		KeySpec:  keySpec,
	})

	if err != nil {
		lAWSKMS.Errorf("could not create private key: %s", err)
		return "", nil, err
	}

	signer, err := newKmsKeyCryptoSignerWrapper(p.kmscli, *key.KeyMetadata.Arn)
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

	_, err = p.kmscli.CreateAlias(ctx, &kms.CreateAliasInput{
		AliasName:   aws.String(fmt.Sprintf(aliasFormat, keyID)),
		TargetKeyId: key.KeyMetadata.Arn,
	})

	if err != nil {
		lAWSKMS.Warnf("Could not create alias for key ARN [%s]: %s", *key.KeyMetadata.Arn, err)
	}

	return keyID, signer, nil
}

func (p *AWSKMSCryptoEngine) ImportRSAPrivateKey(key *rsa.PrivateKey) (string, crypto.Signer, error) {
	keySize := key.PublicKey.N.BitLen()
	var spec types.KeySpec

	switch keySize {
	case 2048:
		spec = types.KeySpecRsa2048
	case 3072:
		spec = types.KeySpecRsa3072
	case 4096:
		spec = types.KeySpecRsa4096
	default:
		err := fmt.Errorf("key size %d not supported by AWS KMS", keySize)
		lAWSKMS.Error(err)
		return "", nil, err
	}

	return p.importKey(key, spec)
}

func (p *AWSKMSCryptoEngine) ImportECDSAPrivateKey(key *ecdsa.PrivateKey) (string, crypto.Signer, error) {
	var spec types.KeySpec

	switch key.Curve {
	case elliptic.P256():
		spec = types.KeySpecEccNistP256
	case elliptic.P384():
		spec = types.KeySpecEccNistP384
	case elliptic.P521():
		spec = types.KeySpecEccNistP521
	default:
		err := fmt.Errorf("ECDSA curve not supported by AWS KMS")
		lAWSKMS.Error(err)
		return "", nil, err
	}

	return p.importKey(key, spec)
}

func (p *AWSKMSCryptoEngine) importKey(key crypto.Signer, spec types.KeySpec) (string, crypto.Signer, error) {
	// 1. Create KMS key
	createKeyOut, err := p.kmscli.CreateKey(context.Background(), &kms.CreateKeyInput{
		Origin:   types.OriginTypeExternal,
		KeySpec:  spec,
		KeyUsage: types.KeyUsageTypeSignVerify,
	})
	if err != nil {
		lAWSKMS.Errorf("could not create key: %s", err)
		return "", nil, err
	}

	// 2. Encode public key to generate alias name
	keyID, err := p.softCryptoEngine.EncodePKIXPublicKeyDigest(key.Public())
	if err != nil {
		lAWSKMS.Errorf("could not encode public key digest: %s", err)
		return "", nil, err
	}

	// 3. Create alias (non-fatal)
	_, err = p.kmscli.CreateAlias(context.Background(), &kms.CreateAliasInput{
		AliasName:   aws.String(fmt.Sprintf(aliasFormat, keyID)),
		TargetKeyId: createKeyOut.KeyMetadata.Arn,
	})
	if err != nil {
		lAWSKMS.Warnf("Could not create alias for key ARN [%s]: %s", *createKeyOut.KeyMetadata.Arn, err)
	}

	// 4. Marshal private key
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		lAWSKMS.Errorf("could not marshal private key: %s", err)
		return "", nil, err
	}

	// 5. Import into KMS
	err = p.importPrivateKeyDer(der, *createKeyOut.KeyMetadata.Arn)
	if err != nil {
		lAWSKMS.Errorf("could not import private key to AWS KMS: %s", err)
		return "", nil, err
	}

	// 6. Return signer
	signer, err := newKmsKeyCryptoSignerWrapper(p.kmscli, *createKeyOut.KeyMetadata.Arn)
	if err != nil {
		lAWSKMS.Errorf("could not create signer: %s", err)
		return "", nil, err
	}

	return keyID, signer, nil
}

func (p *AWSKMSCryptoEngine) importPrivateKeyDer(der []byte, arn string) error {
	symmetricKey := make([]byte, 32)
	_, err := rand.Read(symmetricKey)
	if err != nil {
		lAWSKMS.Errorf("could not generate symmetric encryption key: %s", err)
		return err
	}

	lAWSKMS.Debugf("generated symmetric encryption wrapping key")

	outImportParams, err := p.kmscli.GetParametersForImport(context.Background(), &kms.GetParametersForImportInput{
		WrappingAlgorithm: types.AlgorithmSpecRsaAesKeyWrapSha256,
		KeyId:             &arn,
		WrappingKeySpec:   types.WrappingKeySpecRsa4096,
	})

	if err != nil {
		lAWSKMS.Errorf("could not get import parameters: %s", err)
		return err
	}

	// Encrypt the key material with the wrapping key using AES
	encryptedPrivateKey, err := wrapAESKeyWithPad(symmetricKey, der)
	if err != nil {
		lAWSKMS.Errorf("could not encrypt private key with AES: %s", err)
		return err
	}

	// Encrypt the symmetric key with the wrapping key
	encryptedAesKey, err := encryptWithRSAOAEP(symmetricKey, outImportParams.PublicKey)
	if err != nil {
		lAWSKMS.Errorf("could not encrypt symmetric key with wrapping key: %s", err)
		return err
	}

	combinedEncryptedMaterial := append(encryptedAesKey, encryptedPrivateKey...)

	_, err = p.kmscli.ImportKeyMaterial(context.Background(), &kms.ImportKeyMaterialInput{
		KeyId:                &arn,
		ImportToken:          outImportParams.ImportToken,
		EncryptedKeyMaterial: combinedEncryptedMaterial,
		ExpirationModel:      types.ExpirationModelTypeKeyMaterialDoesNotExpire,
	})
	if err != nil {
		lAWSKMS.Errorf("could not import key material: %s", err)
		return err
	}

	return nil
}

func (p *AWSKMSCryptoEngine) RenameKey(oldID, newID string) error {
	desc, err := p.kmscli.DescribeKey(context.Background(), &kms.DescribeKeyInput{
		KeyId: aws.String(fmt.Sprintf(aliasFormat, oldID)),
	})
	if err != nil {
		lAWSKMS.Errorf("could not get key description: %s", err)
		return err
	}

	_, err = p.kmscli.CreateAlias(context.Background(), &kms.CreateAliasInput{
		AliasName:   aws.String(fmt.Sprintf(aliasFormat, newID)),
		TargetKeyId: desc.KeyMetadata.Arn,
	})
	if err != nil {
		lAWSKMS.Errorf("could not create key: %s", err)
		return err
	}

	_, err = p.kmscli.DeleteAlias(context.Background(), &kms.DeleteAliasInput{
		AliasName: aws.String(fmt.Sprintf(aliasFormat, oldID)),
	})
	if err != nil {
		lAWSKMS.Errorf("could not delete key: %s", err)
	}

	return nil
}

func (p *AWSKMSCryptoEngine) DeleteKey(keyID string) error {
	return fmt.Errorf("cannot delete key [%s]. Go to your aws account and do it manually", keyID)
}

type kmsKeyCryptoSignerWrapper struct {
	keyArn string
	sdk    *kms.Client

	publicKey crypto.PublicKey
}

func newKmsKeyCryptoSignerWrapper(sdk *kms.Client, keyArn string) (crypto.Signer, error) {
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

	return &kmsKeyCryptoSignerWrapper{
		sdk:       sdk,
		keyArn:    keyArn,
		publicKey: pubKey,
	}, nil
}

func (k *kmsKeyCryptoSignerWrapper) Public() crypto.PublicKey {
	return k.publicKey
}
func (k *kmsKeyCryptoSignerWrapper) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
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

func encryptWithRSAOAEP(msg []byte, pubKeyDer []byte) ([]byte, error) {
	// Parse public key
	pubInterface, err := x509.ParsePKIXPublicKey(pubKeyDer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER public key: %w", err)
	}

	pubKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not an RSA key")
	}

	// Encrypt using RSA-OAEP with SHA-256
	label := []byte("") // no label
	hash := sha256.New()
	encryptedKey, err := rsa.EncryptOAEP(hash, rand.Reader, pubKey, msg, label)
	if err != nil {
		return nil, fmt.Errorf("RSA OAEP encryption failed: %w", err)
	}

	// Return the encrypted key
	return encryptedKey, nil
}

// wrapWithPad implements AES-256 key wrap with padding
func wrapAESKeyWithPad(kek, plaintext []byte) ([]byte, error) {
	// Default IV for AES Key Wrap with Padding (RFC 5649)
	var defaultIV = []byte{0xA6, 0x59, 0x59, 0xA6}

	// padKey pads the input according to RFC 5649
	padKey := func(key []byte) []byte {
		m := len(key)
		if m%8 == 0 && m >= 16 {
			return key // No padding needed
		}

		// Append 0x00 padding to make it multiple of 8
		padLen := 8 - (m % 8)
		padded := make([]byte, m+padLen)
		copy(padded, key)
		return padded
	}

	// buildIV builds the 8-byte alternative initial value
	buildIV := func(mli int) []byte {
		iv := make([]byte, 8)
		copy(iv[:4], defaultIV)
		binary.BigEndian.PutUint32(iv[4:], uint32(mli))
		return iv
	}

	// aesEncryptBlock performs ECB AES encryption for a single block
	aesEncryptBlock := func(block cipher.Block, plaintext []byte) []byte {
		dst := make([]byte, len(plaintext))
		block.Encrypt(dst, plaintext)
		return dst
	}

	// xorBlocks returns a ^ b (byte-wise)
	xorBlocks := func(a, b []byte) []byte {
		out := make([]byte, len(a))
		for i := range a {
			out[i] = a[i] ^ b[i]
		}
		return out
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	mli := len(plaintext)
	padded := padKey(plaintext)
	n := len(padded) / 8
	r := make([][]byte, n)
	for i := 0; i < n; i++ {
		r[i] = make([]byte, 8)
		copy(r[i], padded[i*8:(i+1)*8])
	}

	a := buildIV(mli)

	// Perform 6 * n iterations
	for j := 0; j < 6; j++ {
		for i := 0; i < n; i++ {
			b := append(a, r[i]...)
			bEncrypted := aesEncryptBlock(block, b)

			t := uint64(n*j + i + 1)
			tBytes := make([]byte, 8)
			binary.BigEndian.PutUint64(tBytes, t)

			a = xorBlocks(bEncrypted[:8], tBytes)
			copy(r[i], bEncrypted[8:])
		}
	}

	// Output: A || R[0] || R[1] || ...
	result := append(a, []byte{}...)
	for _, block := range r {
		result = append(result, block...)
	}

	return result, nil
}
