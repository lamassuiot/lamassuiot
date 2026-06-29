package services

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

type kmsCryptoSigner struct {
	sdk services.KMSService
	key models.Key
	ctx context.Context
}

func NewKMSCryptoSigner(ctx context.Context, kms models.Key, kmsSDK services.KMSService) crypto.Signer {
	return &kmsCryptoSigner{
		ctx: ctx,
		sdk: kmsSDK,
		key: kms,
	}
}

func (s *kmsCryptoSigner) Public() crypto.PublicKey {
	b, err := base64.StdEncoding.DecodeString(s.key.PublicKey)
	if err != nil {
		return nil
	}

	block, _ := pem.Decode(b)
	if block == nil {
		return nil
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil
	}

	return pub
}

func (s *kmsCryptoSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	// Validate inputs
	if len(digest) == 0 {
		return nil, fmt.Errorf("digest cannot be empty")
	}

	kmsKeyAlg := s.key.Algorithm

	// Default hash function if opts is nil
	hashFunc := crypto.SHA256
	if opts != nil {
		hashFunc = opts.HashFunc()
	}

	// Validate hash function
	if !hashFunc.Available() {
		return nil, fmt.Errorf("hash function %v is not available", hashFunc)
	}

	hashSize := hashFunc.Size() * 8

	// Determine signature algorithm based on key type
	var signAlg string

	switch kmsKeyAlg {
	case x509.ECDSA.String():
		// For ECDSA, hash size should match the key size for optimal security
		// However, we use the hash from opts as it's what the caller requested
		signAlg = fmt.Sprintf("ECDSA_SHA_%d", hashSize)

		// Validate ECDSA key size and hash compatibility
		pub := s.Public()
		if ecPub, ok := pub.(*ecdsa.PublicKey); ok {
			keyBits := ecPub.Curve.Params().BitSize
			// Warn if hash size doesn't match key size (suboptimal but not incorrect)
			if keyBits != hashSize {
				logrus.Warnf("ECDSA key size (%d bits) doesn't match hash size (%d bits) - may be suboptimal", keyBits, hashSize)
			}
		}

	case x509.RSA.String():
		// Check if PSS or PKCS1v15 is requested
		if _, ok := opts.(*rsa.PSSOptions); ok {
			// RSA-PSS signature scheme
			signAlg = fmt.Sprintf("RSASSA_PSS_SHA_%d", hashSize)
		} else {
			// RSA PKCS#1 v1.5 signature scheme (default)
			signAlg = fmt.Sprintf("RSASSA_PKCS1_V1_5_SHA_%d", hashSize)
		}

	// case x509.Ed25519.String():
	// 	// Ed25519 uses its own hash internally, doesn't need external hash specification
	// 	signAlg = "Ed25519"

	default:
		return nil, fmt.Errorf("unsupported key algorithm: %s", kmsKeyAlg)
	}

	// Sign the digest using the KMS service
	response, err := s.sdk.SignMessage(s.ctx, services.SignMessageInput{
		Identifier:  s.key.KeyID,
		Algorithm:   signAlg,
		Message:     digest,
		MessageType: models.Hashed,
	})
	if err != nil {
		return nil, fmt.Errorf("KMS sign operation failed: %w", err)
	}

	return []byte(response.Signature), nil
}
