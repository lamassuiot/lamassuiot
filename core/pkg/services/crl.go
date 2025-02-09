package services

import (
	"context"
	"crypto/x509"
	"math/big"
)

type CRLService interface {
	CalculateCRL(ctx context.Context, input CalculateCRLInput) (*x509.RevocationList, error)
	GetCRL(ctx context.Context, input GetCRLInput) (*x509.RevocationList, error)
}

type GetCRLInput struct {
	CAID       string   `validate:"required"`
	CRLVersion *big.Int `validate:"required"`
}

type CalculateCRLInput struct {
	CAID string `validate:"required"`
}
