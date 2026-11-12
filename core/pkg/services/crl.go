package services

import (
	"context"
	"crypto/x509"
	"math/big"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
)

type CRLService interface {
	CalculateCRL(ctx context.Context, input CalculateCRLInput) (*x509.RevocationList, error)
	GetCRL(ctx context.Context, input GetCRLInput) (*x509.RevocationList, error)
	GetCRLSettings(ctx context.Context, input GetCRLSettingsInput) (*models.CRLSettings, error)
	GetCRLSettingsList(ctx context.Context, input GetCRLSettingsListInput) (string, error)
	UpdateCRLSettings(ctx context.Context, input UpdateCRLSettingsInput) (*models.CRLSettings, error)
	InitCRLSettings(ctx context.Context, caID string) (*models.CRLSettings, error)
}

type GetCRLInput struct {
	// ID is the ID of a CA or, for the CDP of certificates issued before CRL settings moved to the CA ID, the SKI of its key.
	ID         string   `validate:"required"`
	CRLVersion *big.Int `validate:"required"`
}

type CalculateCRLInput struct {
	CAID string `validate:"required"`
}

type GetCRLSettingsInput struct {
	CAID string `validate:"required"`
}

type GetCRLSettingsListInput struct {
	QueryParameters *resources.QueryParameters

	ExhaustiveRun bool //wether to iter all elems
	ApplyFunc     func(settings models.CRLSettings)
}

type UpdateCRLSettingsInput struct {
	CAID    string                    `validate:"required"`
	Options models.CRLSettingsOptions `validate:"required"`
}
