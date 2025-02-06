package services

import (
	"context"
	"crypto/x509"
	"math/big"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

type CRLService interface {
	InitCRLRole(ctx context.Context, input InitCRLRoleInput) (*models.VARole, error)
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

type InitCRLRoleInput struct {
	CAID string `validate:"required"`
}
