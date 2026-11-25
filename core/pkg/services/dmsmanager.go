package services

import (
	"context"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
)

type DMSManagerService interface {
	ESTService
	GetDMSStats(ctx context.Context, input GetDMSStatsInput) (*models.DMSStats, error)
	CreateDMS(ctx context.Context, input CreateDMSInput) (*models.DMS, error)
	UpdateDMS(ctx context.Context, input UpdateDMSInput) (*models.DMS, error)
	UpdateDMSMetadata(ctx context.Context, input UpdateDMSMetadataInput) (*models.DMS, error)
	GetDMSByID(ctx context.Context, input GetDMSByIDInput) (*models.DMS, error)
	GetAll(ctx context.Context, input GetAllInput) (string, error)
	DeleteDMS(ctx context.Context, input DeleteDMSInput) error

	BindIdentityToDevice(ctx context.Context, input BindIdentityToDeviceInput) (*models.BindIdentityToDeviceOutput, error)
}

// PolicyGrantCheck tells whether the caller may grant authz policies itself. The HTTP layer puts it in
// the context of a DMS create or update; without it, an RA can not ask for more than it already has.
type PolicyGrantCheck func(ctx context.Context) (bool, error)

type policyGrantCheckKey struct{}

func WithPolicyGrantCheck(ctx context.Context, check PolicyGrantCheck) context.Context {
	return context.WithValue(ctx, policyGrantCheckKey{}, check)
}

func PolicyGrantCheckFrom(ctx context.Context) PolicyGrantCheck {
	check, _ := ctx.Value(policyGrantCheckKey{}).(PolicyGrantCheck)
	return check
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
	ID       string `validate:"required"`
	Name     string `validate:"required"`
	Metadata map[string]any
	Settings *models.DMSSettings `validate:"required"`
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
