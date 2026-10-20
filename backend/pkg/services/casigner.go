package services

import (
	"context"
	"crypto"
	"crypto/x509"
	"io"
	"slices"
	"strings"

	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
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

// discoverCertificateKey looks, in every crypto engine, for a private key of the given public key to
// link a certificate to, on a best-effort basis: it returns nil rather than an error when there is
// none. The preferred engine is used when it holds the key. Otherwise any engine holding it is, the
// default one first.
func discoverCertificateKey(ctx context.Context, lFunc *logrus.Entry, kms services.KMSService, pub crypto.PublicKey, preferredEngineID string) *models.Key {
	keys, err := kms.GetKeysByPublicKey(ctx, services.GetKeysByPublicKeyInput{PublicKey: pub})
	if err != nil {
		lFunc.Warnf("could not look up the key in KMS: %s", err)
		return nil
	}

	candidates := slices.DeleteFunc(keys, func(key *models.Key) bool { return !key.HasPrivateKey })
	if len(candidates) == 0 {
		return nil
	}
	slices.SortFunc(candidates, func(a, b *models.Key) int { return strings.Compare(a.EngineID, b.EngineID) })

	if i := slices.IndexFunc(candidates, func(key *models.Key) bool { return key.EngineID == preferredEngineID }); i >= 0 {
		return candidates[i]
	}

	chosen := candidates[0]
	if len(candidates) > 1 {
		if engines, err := kms.GetCryptoEngineProvider(ctx); err != nil {
			lFunc.Warnf("could not get the default crypto engine, linking the copy in crypto engine %s: %s", chosen.EngineID, err)
		} else {
			for _, engine := range engines {
				if !engine.Default {
					continue
				}
				if i := slices.IndexFunc(candidates, func(key *models.Key) bool { return key.EngineID == engine.ID }); i >= 0 {
					chosen = candidates[i]
				}
				break
			}
		}
	}

	if preferredEngineID != "" {
		lFunc.Warnf("the key is not in crypto engine %s, linking it to the copy in crypto engine %s", preferredEngineID, chosen.EngineID)
	}
	return chosen
}

// certificateKeyBinding is the KMS binding recording that a certificate, CA certificates included,
// uses its key.
func certificateKeyBinding(cert *x509.Certificate) models.KMSBindResource {
	return models.KMSBindResource{
		ResourceType: models.KMSBindResourceTypeCertificate,
		ResourceID:   helpers.SerialNumberToHexString(cert.SerialNumber),
	}
}
