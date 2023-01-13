package awskms

import (
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
)

var _ crypto.Signer = (*Signer)(nil)

// Signer is a crypto.Signer that uses a AWS KMS backed key. It should be
// initialized via NewSigner
type Signer struct {
	kms         kmsiface.KMSAPI
	keyID       string
	targetKeyID string
	public      crypto.PublicKey
	// hashm maps the given crypto.hash to the alg for the KMS side. it will
	// depend on the key type
	hashm map[crypto.Hash]string
	// psshashm explicitly maps hashes to their pss type. this is because we
	// offer this as an opt-in for RSA keys
	psshashm map[crypto.Hash]string
}

// NewSigner will configure a new Signer using the given KMS client, bound to
// the given key.
func NewSigner(ctx context.Context, kmssvc kmsiface.KMSAPI, keyID string) (*Signer, error) {
	pkresp, err := kmssvc.GetPublicKeyWithContext(ctx, &kms.GetPublicKeyInput{
		KeyId: &keyID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public key for %s: %w", keyID, err)
	}

	if *pkresp.KeyUsage != kms.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf("key usage must be %s, not %s", kms.KeyUsageTypeSignVerify, *pkresp.KeyUsage)
	}

	pub, err := parsePublicKey(pkresp.PublicKey)
	if err != nil {
		return nil, err
	}

	targetKeyID, err := extractKeyID(*pkresp.KeyId)
	if err != nil {
		return nil, err
	}

	s := &Signer{
		kms:         kmssvc,
		keyID:       keyID,
		targetKeyID: targetKeyID,
		public:      pub,
	}

	if err := s.setSigningHashes(pkresp.SigningAlgorithms); err != nil {
		return nil, err
	}

	return s, nil
}

func extractKeyID(arn string) (string, error) {
	arnSegments := strings.Split(arn, ":")
	if len(arnSegments) != 6 {
		return "", fmt.Errorf("unexpected number of ARN segments: %s", arn)
	}

	targetKeyID := arnSegments[5]
	if !strings.HasPrefix(targetKeyID, "key/") {
		return "", fmt.Errorf("unexpected key ID format: %s", targetKeyID)
	}

	return targetKeyID[4:], nil
}

// KeyID returns the resource ID of the AWS KMS key.
func (s *Signer) KeyID() string {
	return s.targetKeyID
}

// Public returns the public key corresponding to the opaque,
// private key.
func (s *Signer) Public() crypto.PublicKey {
	return s.public
}

// Sign signs digest with the private key. By default, for an RSA key a PKCS#1 v1.5 signature, and for an EC
// key a DER-serialised, ASN.1 signature structure will be returned. If the passed options are a *rsa.PSSOptions, the RSA key will return a PSS signature.
//
// Hash is required, as must correspond to a hash the KMS service supports.
//
// rand is unused.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	var hm map[crypto.Hash]string

	switch opts.(type) {
	case *rsa.PSSOptions:
		if len(s.psshashm) < 1 {
			return nil, fmt.Errorf("key does not support pss")
		}
		hm = s.psshashm
	default:
		hm = s.hashm
	}

	alg, ok := hm[opts.HashFunc()]
	if !ok {
		return nil, fmt.Errorf("hash %v not supported", opts.HashFunc())
	}

	sresp, err := s.kms.SignWithContext(context.Background(), &kms.SignInput{
		KeyId:            &s.keyID,
		MessageType:      aws.String(kms.MessageTypeDigest),
		SigningAlgorithm: &alg,
		Message:          digest,
	})
	if err != nil {
		return nil, fmt.Errorf("sign operation failed: %w", err)
	}

	return sresp.Signature, nil
}

func (s *Signer) setSigningHashes(algorithms []*string) error {
	var ecdsa, pss, pkcs15 = make(map[crypto.Hash]string), make(map[crypto.Hash]string), make(map[crypto.Hash]string)

	for _, a := range algorithms {
		switch *a {
		case kms.SigningAlgorithmSpecRsassaPssSha256:
			pss[crypto.SHA256] = kms.SigningAlgorithmSpecRsassaPssSha256
		case kms.SigningAlgorithmSpecRsassaPssSha384:
			pss[crypto.SHA384] = kms.SigningAlgorithmSpecRsassaPssSha384
		case kms.SigningAlgorithmSpecRsassaPssSha512:
			pss[crypto.SHA512] = kms.SigningAlgorithmSpecRsassaPssSha512
		case kms.SigningAlgorithmSpecRsassaPkcs1V15Sha256:
			pkcs15[crypto.SHA256] = kms.SigningAlgorithmSpecRsassaPkcs1V15Sha256
		case kms.SigningAlgorithmSpecRsassaPkcs1V15Sha384:
			pkcs15[crypto.SHA384] = kms.SigningAlgorithmSpecRsassaPkcs1V15Sha384
		case kms.SigningAlgorithmSpecRsassaPkcs1V15Sha512:
			pkcs15[crypto.SHA512] = kms.SigningAlgorithmSpecRsassaPkcs1V15Sha512
		case kms.SigningAlgorithmSpecEcdsaSha256:
			ecdsa[crypto.SHA256] = kms.SigningAlgorithmSpecEcdsaSha256
		case kms.SigningAlgorithmSpecEcdsaSha384:
			ecdsa[crypto.SHA384] = kms.SigningAlgorithmSpecEcdsaSha384
		case kms.SigningAlgorithmSpecEcdsaSha512:
			ecdsa[crypto.SHA512] = kms.SigningAlgorithmSpecEcdsaSha512
		}
	}

	// always set the pss hashes, to handle the user explicitly opting in
	s.psshashm = pss

	// set up the defaults
	if len(ecdsa) > 0 {
		s.hashm = ecdsa
		return nil
	}
	if len(pkcs15) > 0 {
		s.hashm = pkcs15
		return nil
	}
	if len(pss) > 0 {
		s.hashm = pss
		return nil
	}

	return fmt.Errorf("no valid signing hashes found for key %s", s.keyID)
}
