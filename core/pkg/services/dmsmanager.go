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

	// ApproveCMPTransaction releases a PENDING transaction in the phased
	// (admin-gated) workflow: it issues the certificate from the stored CSR and
	// transitions the transaction to ISSUED so the EE can retrieve it via
	// pollReq. Returns the updated transaction. Errors with
	// ErrCMPTransactionNotFound / ErrCMPTransactionNotPending when the
	// transaction is missing, belongs to another DMS, or is not awaiting
	// approval.
	ApproveCMPTransaction(ctx context.Context, input ApproveCMPTransactionInput) (*storage.CMPTransaction, error)

	// RejectCMPTransaction denies a PENDING transaction in the phased
	// (admin-gated) workflow without issuing a certificate. The row moves to
	// ISSUE_FAILED carrying the rejection reason, which pollReq surfaces back
	// to the EE as an error PKIMessage. Same error semantics as
	// ApproveCMPTransaction.
	RejectCMPTransaction(ctx context.Context, input RejectCMPTransactionInput) (*storage.CMPTransaction, error)
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

type ApproveCMPTransactionInput struct {
	DMSID         string `validate:"required"`
	TransactionID string `validate:"required"`
}

type RejectCMPTransactionInput struct {
	DMSID         string `validate:"required"`
	TransactionID string `validate:"required"`
	// Reason is the administrator-supplied reason. Free-form text; an empty
	// value falls back to a generic message so pollReq always surfaces a
	// meaningful explanation to the EE.
	Reason string
}
