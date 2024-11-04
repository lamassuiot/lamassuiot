package services

import (
	"context"
	"crypto"
	"crypto/x509"
	"io"

	"github.com/lamassuiot/lamassuiot/v2/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/services"
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
	if opts.HashFunc().Size()*8 == 256 {
		if caKeyAlg == x509.ECDSA {
			signAlg = "ECDSA_SHA_256"
		} else if caKeyAlg == x509.RSA {
			signAlg = "RSASSA_PKCS1_V1_5_SHA_256"
		}
	} else {
		logrus.Warnf("using default %s sing alg for client. '%s' no match", signAlg, caKeyAlg)
	}

	return s.sdk.SignatureSign(s.ctx, services.SignatureSignInput{
		CAID:             s.ca.ID,
		Message:          digest,
		MessageType:      models.Hashed,
		SigningAlgorithm: signAlg,
	})
}
