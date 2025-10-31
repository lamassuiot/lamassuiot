package services

import (
	"context"
	"crypto"
	"crypto/x509"
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
	return s.key.PublicKey
}

func (s *kmsCryptoSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	signAlg := "RSASSA_PKCS1_V1_5_SHA_256"
	kmsKeyAlg := s.key.Algorithm
	caHashFunc := opts.HashFunc()
	caHashSize := caHashFunc.Size() * 8

	switch kmsKeyAlg {
	//TODO: ECDSA SHA size should be determined by key size. Not applicable to RSA
	case x509.ECDSA.String():
		signAlg = fmt.Sprintf("ECDSA_SHA_%d", caHashSize)
	case x509.RSA.String():
		signAlg = fmt.Sprintf("RSASSA_PKCS1_V1_5_SHA_%d", caHashSize)
	default:
		logrus.Warnf("using default %s sign alg for client. '%s' no match", signAlg, kmsKeyAlg)
	}

	response, err := s.sdk.SignMessage(s.ctx, services.SignMessageInput{
		Identifier:  s.key.KeyID,
		Algorithm:   signAlg,
		Message:     digest,
		MessageType: models.Raw,
	})
	if err != nil {
		return nil, err
	}

	return []byte(response.Signature), nil
}
