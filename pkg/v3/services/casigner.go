package services

import (
	"crypto"
	"crypto/x509"
	"io"

	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/sirupsen/logrus"
)

type caSignerImpl struct {
	sdk CAService
	ca  *models.CACertificate
}

func NewCASigner(ca *models.CACertificate, caSDK CAService) crypto.Signer {
	return &caSignerImpl{
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
	if opts.HashFunc().Size() == 256 {
		if caKeyAlg == x509.ECDSA {
			signAlg = "ECDSA_SHA_256"
		} else if caKeyAlg == x509.RSA {
			signAlg = "RSASSA_PKCS1_V1_5_SHA_256"
		}
	} else {
		logrus.Warnf("using default %s sing alg for client. '%s' no match", signAlg, caKeyAlg)
	}

	return s.sdk.SignatureSign(SignatureSignInput{
		CAID:             s.ca.ID,
		Message:          digest,
		MessageType:      models.Hashed,
		SigningAlgorithm: signAlg,
	})
}
