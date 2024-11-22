package services

import (
	"context"

	"github.com/lamassuiot/lamassuiot/v3/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/resources"
)

type DMSManagerService interface {
	ESTService
	GetDMSStats(ctx context.Context, input GetDMSStatsInput) (*models.DMSStats, error)
	CreateDMS(ctx context.Context, input CreateDMSInput) (*models.DMS, error)
	UpdateDMS(ctx context.Context, input UpdateDMSInput) (*models.DMS, error)
	GetDMSByID(ctx context.Context, input GetDMSByIDInput) (*models.DMS, error)
	GetAll(ctx context.Context, input GetAllInput) (string, error)

	BindIdentityToDevice(ctx context.Context, input BindIdentityToDeviceInput) (*models.BindIdentityToDeviceOutput, error)
}

type GetDMSStatsInput struct{}

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

type BindIdentityToDeviceInput struct {
	DeviceID                string
	CertificateSerialNumber string
	BindMode                models.DeviceEventType
}
