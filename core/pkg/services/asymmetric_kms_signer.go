package services

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

type keyPairCryptoSigner struct {
	ctx context.Context
	kp  models.KeyPair
	svc AsymmetricKMSService
}

func NewKeyPairCryptoSigner(ctx context.Context, kp models.KeyPair, svc AsymmetricKMSService) crypto.Signer {
	return &keyPairCryptoSigner{
		ctx: ctx,
		kp:  kp,
		svc: svc,
	}
}

func (s *keyPairCryptoSigner) Public() crypto.PublicKey {
	return s.kp.PublicKey.Key
}

func (s *keyPairCryptoSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	digestLen := len(digest)

	var algorithm x509.SignatureAlgorithm

	switch s.kp.Algorithm {
	case x509.ECDSA:
		switch digestLen {
		case 32:
			algorithm = x509.ECDSAWithSHA256
		case 48:
			algorithm = x509.ECDSAWithSHA384
		case 64:
			algorithm = x509.ECDSAWithSHA512
		default:
			return nil, fmt.Errorf("unsupported digest length %d for ECDSA", digestLen)
		}

	case x509.RSA:
		switch opts.(type) {
		case *rsa.PSSOptions:
			switch digestLen {
			case 32:
				algorithm = x509.SHA256WithRSAPSS
			case 48:
				algorithm = x509.SHA384WithRSAPSS
			case 64:
				algorithm = x509.SHA512WithRSAPSS
			default:
				return nil, fmt.Errorf("unsupported digest length %d for RSA", digestLen)
			}
		default:
			switch digestLen {
			case 32:
				algorithm = x509.SHA256WithRSA
			case 48:
				algorithm = x509.SHA384WithRSA
			case 64:
				algorithm = x509.SHA512WithRSA
			default:
				return nil, fmt.Errorf("unsupported digest length %d for RSA", digestLen)
			}
		}

	default:
		return nil, fmt.Errorf("unsupported algorithm %s", s.kp.Algorithm)
	}

	return s.svc.Sign(s.ctx, SignInput{
		KeyID:              s.kp.KeyID,
		Message:            digest,
		MessageType:        models.Hashed,
		SignatureAlgorithm: algorithm,
	})
}
