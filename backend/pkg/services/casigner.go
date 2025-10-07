package services

import (
	"context"
	"crypto"
	"crypto/x509"
	"io"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

type certSignerImpl struct {
	sdk  services.KMSService
	cert *x509.Certificate
	ctx  context.Context
}

func NewCertificateSigner(ctx context.Context, cert *models.Certificate, kmsSDK services.KMSService) crypto.Signer {
	x509Cert := (*x509.Certificate)(cert.Certificate)

	return &certSignerImpl{
		ctx:  ctx,
		sdk:  kmsSDK,
		cert: x509Cert,
	}
}

func (s *certSignerImpl) Public() crypto.PublicKey {
	return s.cert.PublicKey
}

func (s *certSignerImpl) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	l := logrus.New()
	l.SetOutput(io.Discard)

	ski, err := helpers.GetSubjectKeyID(logrus.NewEntry(l), s.cert)
	if err != nil {
		return nil, err
	}

	key, err := s.sdk.GetKey(s.ctx, services.GetKeyInput{
		Identifier: ski,
	})

	if err != nil {
		return nil, err
	}

	kmsSigner := NewKMSCryptoSigner(s.ctx, *key, s.sdk)
	return kmsSigner.Sign(rand, digest, opts)
}
