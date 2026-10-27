package services

import (
	"context"
	"crypto"
	"crypto/x509"
	"io"
	"slices"
	"strings"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/sirupsen/logrus"
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

// discoverCertificateKey looks, in every crypto engine, for the private key of a certificate not yet
// linked to one. It prefers the requested engine, then the default one, then any engine holding it,
// and returns nil when there is none: a lookup failure only means the certificate stays keyless.
func discoverCertificateKey(ctx context.Context, lFunc *logrus.Entry, kms services.KMSService, pub crypto.PublicKey, preferredEngineID string) *models.Key {
	keys, err := kms.GetKeysByPublicKey(ctx, services.GetKeysByPublicKeyInput{PublicKey: pub})
	if err != nil {
		lFunc.Warnf("could not look up the certificate key in the KMS: %s", err)
		return nil
	}

	candidates := slices.DeleteFunc(keys, func(key *models.Key) bool { return !key.HasPrivateKey })
	if len(candidates) == 0 {
		return nil
	}
	slices.SortFunc(candidates, func(a, b *models.Key) int { return strings.Compare(a.EngineID, b.EngineID) })

	inEngine := func(engineID string) *models.Key {
		if i := slices.IndexFunc(candidates, func(key *models.Key) bool { return key.EngineID == engineID }); i >= 0 {
			return candidates[i]
		}
		return nil
	}

	if preferredEngineID != "" {
		if key := inEngine(preferredEngineID); key != nil {
			return key
		}
	}

	chosen := candidates[0]
	if engines, err := kms.GetCryptoEngineProvider(ctx); err != nil {
		lFunc.Warnf("could not get the default crypto engine: %s", err)
	} else {
		for _, engine := range engines {
			if engine.Default {
				if key := inEngine(engine.ID); key != nil {
					chosen = key
				}
				break
			}
		}
	}

	if preferredEngineID != "" {
		lFunc.Warnf("the key is not in crypto engine %s, linking the copy in crypto engine %s", preferredEngineID, chosen.EngineID)
	}
	return chosen
}
