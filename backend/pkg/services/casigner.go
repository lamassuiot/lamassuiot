package services

import (
	"context"
	"crypto"
	"crypto/x509"
	"io"

	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
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
	key, err := findCertificateKey(s.ctx, s.sdk, s.cert.PublicKey, s.engineID)
	if err != nil {
		return nil, err
	}

	kmsSigner := NewKMSCryptoSigner(s.ctx, *key, s.sdk)
	return kmsSigner.Sign(rand, digest, opts)
}

// findCertificateKey returns the KMS key of a certificate's key pair, found by its public key: the
// certificate's SKI is whatever its issuer wrote. A key is identified by (keyID, engineID), so without
// an engine it resolves only while a single engine holds the key.
func findCertificateKey(ctx context.Context, kms services.KMSService, pub crypto.PublicKey, engineID string) (*models.Key, error) {
	keys, err := kms.GetKeysByPublicKey(ctx, services.GetKeysByPublicKeyInput{
		PublicKey: pub,
		EngineID:  engineID,
	})
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

// certificateKeyBinding is the KMS binding recording that a certificate, CA certificates included,
// uses its key.
func certificateKeyBinding(cert *x509.Certificate) models.KMSBindResource {
	return models.KMSBindResource{
		ResourceType: models.KMSBindResourceTypeCertificate,
		ResourceID:   helpers.SerialNumberToHexString(cert.SerialNumber),
	}
}
