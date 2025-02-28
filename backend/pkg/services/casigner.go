package services

import (
	"context"
	"crypto"
	"io"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

type caSignerImpl struct {
	kms services.AsymmetricKMSService
	ca  *models.CACertificate
	ctx context.Context
}

func NewCASigner(ctx context.Context, ca *models.CACertificate, kms services.AsymmetricKMSService) crypto.Signer {
	return &caSignerImpl{
		ctx: ctx,
		kms: kms,
		ca:  ca,
	}
}

func (s *caSignerImpl) Public() crypto.PublicKey {
	return s.ca.Certificate.Certificate.PublicKey
}

func (s *caSignerImpl) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	res, err := s.kms.Sign(s.ctx, services.KMSSignInput{
		KeyID:              s.ca.Certificate.KeyID,
		Message:            digest,
		MessageType:        models.Hashed,
		SignatureAlgorithm: "",
	})

	if err != nil {
		return nil, err
	}

	return res, nil
}
