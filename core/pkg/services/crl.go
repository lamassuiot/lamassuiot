package services

import (
	"context"
	"crypto/x509"
	"math/big"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
)

type CRLService interface {
	CalculateCRL(ctx context.Context, input CalculateCRLInput) (*x509.RevocationList, error)
	GetCRL(ctx context.Context, input GetCRLInput) (*x509.RevocationList, error)
	GetCRLSettings(ctx context.Context, input GetCRLSettingsInput) (*models.CRLSettings, error)
	GetCRLSettingsList(ctx context.Context, input GetCRLSettingsListInput) (string, error)
	UpdateCRLSettings(ctx context.Context, input UpdateCRLSettingsInput) (*models.CRLSettings, error)
	// InitCRLSettings returns nil settings without error if none exist and the CA certificate has no KMS engine or key ID.
	InitCRLSettings(ctx context.Context, caID string) (*models.CRLSettings, error)
	// FinalizeCRLSettings moves ACTIVE settings to FINAL, publishing their final CRL first if asked to. Settings that
	// are not ACTIVE are returned unchanged.
	FinalizeCRLSettings(ctx context.Context, input FinalizeCRLSettingsInput) (*models.CRLSettings, error)
	// ArchiveCRLSettings moves the settings of a deleted CA to ARCHIVED.
	ArchiveCRLSettings(ctx context.Context, input ArchiveCRLSettingsInput) (*models.CRLSettings, error)
	// DeleteCRLSettings purges ARCHIVED settings. Their published CRLs stay in the bucket.
	DeleteCRLSettings(ctx context.Context, input DeleteCRLSettingsInput) error
	// ReconcileCRLSettings moves the settings to the status the CA they belong to calls for.
	ReconcileCRLSettings(ctx context.Context, input ReconcileCRLSettingsInput) (*models.CRLSettings, error)
}

type FinalizeCRLSettingsInput struct {
	CAID string `validate:"required"`
	// FinalCRL publishes a last CRL, valid until FinalCRLNextUpdate, before the settings stop signing CRLs.
	FinalCRL           bool
	FinalCRLNextUpdate time.Time
}

type ArchiveCRLSettingsInput struct {
	CAID string `validate:"required"`
}

type DeleteCRLSettingsInput struct {
	CAID string `validate:"required"`
}

type ReconcileCRLSettingsInput struct {
	CAID string `validate:"required"`
	// RevokedBefore, when set, leaves alone a CA revoked after it: UpdateCAStatus stores the CA as revoked before it
	// revokes its certificates, so a final CRL issued meanwhile could miss some. The ca.status.update event, published
	// once they are all revoked, finalizes such CAs.
	RevokedBefore time.Time
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
