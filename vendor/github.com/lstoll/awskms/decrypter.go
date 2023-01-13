package awskms

import (
	"context"
	"crypto"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
)

var _ crypto.Decrypter = (*Decrypter)(nil)

// EncryptionAlgorithm https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html#KMS-Decrypt-request-EncryptionAlgorithm
type EncryptionAlgorithm string

const (
	// EncryptionAlgorithmOaepSha256 = RSAES_OAEP_SHA_256 (https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html#KMS-Decrypt-request-EncryptionAlgorithm)
	EncryptionAlgorithmOaepSha256 = kms.AlgorithmSpecRsaesOaepSha256
	// EncryptionAlgorithmOaepSha1 = RSAES_OAEP_SHA_1 (https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html#KMS-Decrypt-request-EncryptionAlgorithm)
	EncryptionAlgorithmOaepSha1 = kms.AlgorithmSpecRsaesOaepSha1
)

// Decrypter implents a crypto.Decrypter that uses a RSA key stored in AWS
// It should be initialized via NewDecrypter
type Decrypter struct {
	kms    kmsiface.KMSAPI
	keyID  string
	public crypto.PublicKey
}

// NewDecrypter will configure a new decrypter using the given KMS client, bound
// to the given key.
func NewDecrypter(ctx context.Context, kmssvc kmsiface.KMSAPI, keyID string) (*Decrypter, error) {
	pkresp, err := kmssvc.GetPublicKeyWithContext(ctx, &kms.GetPublicKeyInput{
		KeyId: &keyID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public key for %s: %w", keyID, err)
	}

	if *pkresp.KeyUsage != kms.KeyUsageTypeEncryptDecrypt {
		return nil, fmt.Errorf("key usage must be %s, not %s", kms.KeyUsageTypeSignVerify, *pkresp.KeyUsage)
	}

	pub, err := parsePublicKey(pkresp.PublicKey)
	if err != nil {
		return nil, err
	}

	return &Decrypter{
		kms:    kmssvc,
		keyID:  keyID,
		public: pub,
	}, nil
}

// Public returns the public key corresponding to the opaque,
// private key.
func (d *Decrypter) Public() crypto.PublicKey {
	return d.public
}

// DecrypterOpts implements crypto.DecrypterOpts for this Decrypter
type DecrypterOpts struct {
	// EncryptionAlgorithm indicates the encryption algorithm that was used.
	// If not set, defaults to EncryptionAlgorithmOaepSha256
	EncryptionAlgorithm EncryptionAlgorithm
}

// Decrypt decrypts msg. If opts are nil, EncryptionAlgorithmOaepSha256 will be
// used.
func (d *Decrypter) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {

	var o DecrypterOpts

	od, ok := opts.(*DecrypterOpts)
	if !ok && opts != nil {
		return nil, fmt.Errorf("passed options are of unknown type %T", opts)
	}
	if od != nil {
		o = *od
	}

	var alg string = EncryptionAlgorithmOaepSha256
	if o.EncryptionAlgorithm != "" {
		alg = string(o.EncryptionAlgorithm)
	}

	dresp, err := d.kms.DecryptWithContext(context.Background(), &kms.DecryptInput{
		KeyId:               &d.keyID,
		CiphertextBlob:      msg,
		EncryptionAlgorithm: &alg,
	})
	if err != nil {
		return nil, fmt.Errorf("sign operation failed: %w", err)
	}

	return dresp.Plaintext, nil
}
