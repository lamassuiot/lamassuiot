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

type caSignerImpl struct {
	sdk services.CAService
	ca  *models.CACertificate
	ctx context.Context
}

func NewCASigner(ctx context.Context, ca *models.CACertificate, caSDK services.CAService) crypto.Signer {
	return &caSignerImpl{
		ctx: ctx,
		sdk: caSDK,
		ca:  ca,
	}
}

func (s *caSignerImpl) Public() crypto.PublicKey {
	return s.ca.Certificate.Certificate.PublicKey
}

func (s *caSignerImpl) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	signAlg := "RSASSA_PKCS1_V1_5_SHA_256"
	caKeyAlg := s.ca.Certificate.Certificate.PublicKeyAlgorithm
	caHashFunc := opts.HashFunc()
	caHashSize := caHashFunc.Size() * 8
	switch caKeyAlg {
	case x509.ECDSA:
		signAlg = fmt.Sprintf("ECDSA_SHA_%d", caHashSize)
	case x509.RSA:
		signAlg = fmt.Sprintf("RSASSA_PKCS1_V1_5_SHA_%d", caHashSize)
	default:
		logrus.Warnf("using default %s sing alg for client. '%s' no match", signAlg, caKeyAlg)
	}

	return s.sdk.SignatureSign(s.ctx, services.SignatureSignInput{
		CAID:             s.ca.ID,
		Message:          digest,
		MessageType:      models.Hashed,
		SigningAlgorithm: signAlg,
	})
}
