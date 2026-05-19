package services

import (
	"context"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
)

type DMSManagerService interface {
	ESTService
	LightweightCMPService

	GetDMSStats(ctx context.Context, input GetDMSStatsInput) (*models.DMSStats, error)
	CreateDMS(ctx context.Context, input CreateDMSInput) (*models.DMS, error)
	UpdateDMS(ctx context.Context, input UpdateDMSInput) (*models.DMS, error)
	UpdateDMSMetadata(ctx context.Context, input UpdateDMSMetadataInput) (*models.DMS, error)
	GetDMSByID(ctx context.Context, input GetDMSByIDInput) (*models.DMS, error)
	GetAll(ctx context.Context, input GetAllInput) (string, error)
	DeleteDMS(ctx context.Context, input DeleteDMSInput) error

	BindIdentityToDevice(ctx context.Context, input BindIdentityToDeviceInput) (*models.BindIdentityToDeviceOutput, error)

	// GetCMPTransactionsByDMS lists CMP enrollment transactions for the given
	// DMS, applying the standard pagination/sort/filter machinery. Both
	// in-flight (PENDING/ISSUED) and stale rows are returned so operators
	// can inspect failed or abandoned enrollments.
	GetCMPTransactionsByDMS(ctx context.Context, input GetCMPTransactionsByDMSInput) (string, error)
}

type GetDMSStatsInput struct {
	QueryParameters *resources.QueryParameters
}

type CreateDMSInput struct {
	ID       string `validate:"required"`
	Name     string `validate:"required"`
	Metadata map[string]any
	Settings models.DMSSettings `validate:"required"`
}

type UpdateDMSInput struct {
	DMS models.DMS `validate:"required"`
}

type GetDMSByIDInput struct {
	ID string `validate:"required"`
}

type GetAllInput struct {
	resources.ListInput[models.DMS]
}

type DeleteDMSInput struct {
	ID string `validate:"required"`
}

type UpdateDMSMetadataInput struct {
	ID      string                  `validate:"required"`
	Patches []models.PatchOperation `validate:"required"`
}

type BindIdentityToDeviceInput struct {
	DeviceID                string
	CertificateSerialNumber string
	BindMode                models.DeviceEventType
}

type GetCMPTransactionsByDMSInput struct {
	DMSID string `validate:"required"`
	resources.ListInput[storage.CMPTransaction]
}
