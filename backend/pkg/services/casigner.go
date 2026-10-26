package services

import (
	"context"
	"crypto"
	"crypto/x509"
	"io"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
)

type certSignerImpl struct {
	sdk      services.KMSService
	cert     *x509.Certificate
	engineID string
	keyID    string
	ctx      context.Context
}

func NewCertificateSigner(ctx context.Context, cert *models.Certificate, kmsSDK services.KMSService) crypto.Signer {
	x509Cert := (*x509.Certificate)(cert.Certificate)

	return &certSignerImpl{
		ctx:      ctx,
		sdk:      kmsSDK,
		cert:     x509Cert,
		engineID: cert.EngineID,
		keyID:    cert.KeyID,
	}
}

func (s *certSignerImpl) Public() crypto.PublicKey {
	return s.cert.PublicKey
}

func (s *certSignerImpl) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	key, err := findCertificateKey(s.ctx, s.sdk, s.cert.PublicKey, s.engineID, s.keyID)
	if err != nil {
		return nil, err
	}

	kmsSigner := NewKMSCryptoSigner(s.ctx, *key, s.sdk)
	return kmsSigner.Sign(rand, digest, opts)
}

// findCertificateKey returns the KMS key of a certificate. A key is identified by (keyID, engineID);
// certificates stored before they recorded their keyID find it by public key instead, since their
// SKI is whatever their issuer wrote.
func findCertificateKey(ctx context.Context, kms services.KMSService, pub crypto.PublicKey, engineID, keyID string) (*models.Key, error) {
	if keyID != "" {
		identifier := keyID
		if engineID != "" {
			identifier = buildPKCS11ID(engineID, keyID, "private")
		}
		return kms.GetKey(ctx, services.GetKeyInput{Identifier: identifier})
	}

	keys, err := kms.GetKeysByPublicKey(ctx, services.GetKeysByPublicKeyInput{PublicKey: pub, EngineID: engineID})
	if err != nil {
		return nil, err
	}

	switch len(keys) {
	case 0:
		return nil, errs.ErrKeyNotFound
	case 1:
		return keys[0], nil
	default:
		return nil, errs.ErrKeyEngineRequired
	}
}
