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
	sdk      services.KMSService
	cert     *x509.Certificate
	engineID string
	ctx      context.Context
}

func NewCertificateSigner(ctx context.Context, cert *models.Certificate, kmsSDK services.KMSService) crypto.Signer {
	x509Cert := (*x509.Certificate)(cert.Certificate)

	return &certSignerImpl{
		ctx:      ctx,
		sdk:      kmsSDK,
		cert:     x509Cert,
		engineID: cert.EngineID,
	}
}

func (s *certSignerImpl) Public() crypto.PublicKey {
	return s.cert.PublicKey
}

func (s *certSignerImpl) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	l := logrus.New()
	l.SetOutput(io.Discard)

	ski, err := helpers.GetSubjectKeyID(s.ctx, logrus.NewEntry(l), s.cert)
	if err != nil {
		return nil, err
	}

	// The certificate's key is addressed by (keyID, engineID): the SKI alone would stop
	// resolving as soon as another engine holds a copy of the same key.
	identifier := ski
	if s.engineID != "" {
		identifier = buildPKCS11ID(s.engineID, ski, "private")
	}

	key, err := s.sdk.GetKey(s.ctx, services.GetKeyInput{
		Identifier: identifier,
	})

	if err != nil {
		return nil, err
	}

	kmsSigner := NewKMSCryptoSigner(s.ctx, *key, s.sdk)
	return kmsSigner.Sign(rand, digest, opts)
}
