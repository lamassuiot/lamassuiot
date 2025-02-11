package services

import (
	"context"
	"crypto/x509"
	"math/big"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
)

type CRLService interface {
	CalculateCRL(ctx context.Context, input CalculateCRLInput) (*x509.RevocationList, error)
	GetCRL(ctx context.Context, input GetCRLInput) (*x509.RevocationList, error)
	GetVARole(ctx context.Context, input GetVARoleInput) (*models.VARole, error)
	GetVARoles(ctx context.Context, input GetVARolesInput) (string, error)
	UpdateVARole(ctx context.Context, input UpdateVARoleInput) (*models.VARole, error)
}

type GetCRLInput struct {
	CAID       string   `validate:"required"`
	CRLVersion *big.Int `validate:"required"`
}

type CalculateCRLInput struct {
	CAID string `validate:"required"`
}

type GetVARoleInput struct {
	CAID string `validate:"required"`
}

type GetVARolesInput struct {
	QueryParameters *resources.QueryParameters

	ExhaustiveRun bool //wether to iter all elems
	ApplyFunc     func(role models.VARole)
}

type UpdateVARoleInput struct {
	CAID    string           `validate:"required"`
	CRLRole models.VACRLRole `validate:"required"`
}
