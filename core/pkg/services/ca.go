package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
)

type CAService interface {
	GetStats(ctx context.Context) (*models.CAStats, error)
	GetStatsByCAID(ctx context.Context, input GetStatsByCAIDInput) (map[models.CertificateStatus]int, error)

	GetCryptoEngineProvider(ctx context.Context) ([]*models.CryptoEngineProvider, error)

	CreateCA(ctx context.Context, input CreateCAInput) (*models.CACertificate, error)
	RequestCACSR(ctx context.Context, input RequestCAInput) (*models.CACertificateRequest, error)
	ImportCA(ctx context.Context, input ImportCAInput) (*models.CACertificate, error)
	GetCAByID(ctx context.Context, input GetCAByIDInput) (*models.CACertificate, error)
	GetCAs(ctx context.Context, input GetCAsInput) (string, error)
	GetCAsByCommonName(ctx context.Context, input GetCAsByCommonNameInput) (string, error)
	UpdateCAStatus(ctx context.Context, input UpdateCAStatusInput) (*models.CACertificate, error)
	UpdateCAMetadata(ctx context.Context, input UpdateCAMetadataInput) (*models.CACertificate, error)
	UpdateCAIssuanceExpiration(ctx context.Context, input UpdateCAIssuanceExpirationInput) (*models.CACertificate, error)
	DeleteCA(ctx context.Context, input DeleteCAInput) error

	SignatureSign(ctx context.Context, input SignatureSignInput) ([]byte, error)
	SignatureVerify(ctx context.Context, input SignatureVerifyInput) (bool, error)

	SignCertificate(ctx context.Context, input SignCertificateInput) (*models.Certificate, error)
	CreateCertificate(ctx context.Context, input CreateCertificateInput) (*models.Certificate, error)
	ImportCertificate(ctx context.Context, input ImportCertificateInput) (*models.Certificate, error)

	GetCertificateBySerialNumber(ctx context.Context, input GetCertificatesBySerialNumberInput) (*models.Certificate, error)
	GetCertificates(ctx context.Context, input GetCertificatesInput) (string, error)
	GetCertificatesByCA(ctx context.Context, input GetCertificatesByCAInput) (string, error)
	GetCertificatesByExpirationDate(ctx context.Context, input GetCertificatesByExpirationDateInput) (string, error)
	GetCertificatesByCaAndStatus(ctx context.Context, input GetCertificatesByCaAndStatusInput) (string, error)
	// GetCertificatesByExpirationDateAndCA(input GetCertificatesByExpirationDateInput) (string, error)
	GetCertificatesByStatus(ctx context.Context, input GetCertificatesByStatusInput) (string, error)
	// GetCertificatesByStatusAndCA(input GetCertificatesByExpirationDateInput) (string, error)
	UpdateCertificateStatus(ctx context.Context, input UpdateCertificateStatusInput) (*models.Certificate, error)
	UpdateCertificateMetadata(ctx context.Context, input UpdateCertificateMetadataInput) (*models.Certificate, error)

	GetCARequestByID(ctx context.Context, input GetByIDInput) (*models.CACertificateRequest, error)
	DeleteCARequestByID(ctx context.Context, input GetByIDInput) error
	GetCARequests(ctx context.Context, input GetItemsInput[models.CACertificateRequest]) (string, error)
}

type GetStatsByCAIDInput struct {
	CAID string
}

type SignInput struct {
	CAID               string
	Message            []byte
	MessageType        models.SignMessageType
	SignatureAlgorithm string
}

type IssueCACSRInput struct {
	CAID        string                 `validate:"required"`
	KeyMetadata models.KeyMetadata     `validate:"required"`
	Subject     models.Subject         `validate:"required"`
	CAType      models.CertificateType `validate:"required"`
	EngineID    string
}

type IssueCAInput struct {
	ParentCA     *models.CACertificate
	KeyMetadata  models.KeyMetadata     `validate:"required"`
	Subject      models.Subject         `validate:"required"`
	CAType       models.CertificateType `validate:"required"`
	CAExpiration models.Validity
	EngineID     string
	CAID         string `validate:"required"`
}

type IssueCAOutput struct {
	KeyID       string
	Certificate *x509.Certificate
}

type IssueCACSROutput struct {
	KeyID string
	CSR   *x509.CertificateRequest
}

type ImportCAInput struct {
	ID                 string
	CAType             models.CertificateType    `validate:"required,ne=MANAGED"`
	IssuanceExpiration models.Validity           `validate:"required"`
	CACertificate      *models.X509Certificate   `validate:"required"`
	CAChain            []*models.X509Certificate //Parent CAs. They MUST be sorted as follows. 0: Root-CA; 1: Subordinate CA from Root-CA; ...
	CARSAKey           *rsa.PrivateKey
	CAECKey            *ecdsa.PrivateKey
	KeyType            models.KeyType
	EngineID           string
	CARequestID        string
}

type CreateCAInput struct {
	ID                 string
	ParentID           string
	KeyMetadata        models.KeyMetadata `validate:"required"`
	Subject            models.Subject     `validate:"required"`
	IssuanceExpiration models.Validity    `validate:"required"`
	CAExpiration       models.Validity    `validate:"required"`
	EngineID           string
	Metadata           map[string]any
}

type RequestCAInput struct {
	ID          string
	KeyMetadata models.KeyMetadata `validate:"required"`
	Subject     models.Subject     `validate:"required"`
	EngineID    string
	Metadata    map[string]any
}

type GetByIDInput struct {
	ID string `validate:"required"`
}

type GetCAByIDInput struct {
	CAID string `validate:"required"`
}

type GetCAsInput struct {
	QueryParameters *resources.QueryParameters

	ExhaustiveRun bool //wether to iter all elems
	ApplyFunc     func(ca models.CACertificate)
}

type GetItemsInput[T any] struct {
	QueryParameters *resources.QueryParameters

	ExhaustiveRun bool //wether to iter all elems
	ApplyFunc     func(ca T)
}

type GetCABySerialNumberInput struct {
	SerialNumber string `validate:"required"`
}

type GetCAsByCommonNameInput struct {
	CommonName string

	QueryParameters *resources.QueryParameters
	ExhaustiveRun   bool //wether to iter all elems
	ApplyFunc       func(cert models.CACertificate)
}

type UpdateCAStatusInput struct {
	CAID             string                   `validate:"required"`
	Status           models.CertificateStatus `validate:"required"`
	RevocationReason models.RevocationReason
}

type UpdateCAIssuanceExpirationInput struct {
	CAID               string          `validate:"required"`
	IssuanceExpiration models.Validity `validate:"required"`
}

type UpdateCAMetadataInput struct {
	CAID    string                  `validate:"required"`
	Patches []models.PatchOperation `validate:"required"`
}

type DeleteCAInput struct {
	CAID string `validate:"required"`
}

type SignCertificateInput struct {
	CAID            string                         `validate:"required"`
	CertRequest     *models.X509CertificateRequest `validate:"required"`
	IssuanceProfile models.IssuanceProfile         `validate:"required"`
}

type CreateCertificateInput struct {
	KeyMetadata models.KeyMetadata `validate:"required"`
	Subject     models.Subject     `validate:"required"`
}

type ImportCertificateInput struct {
	Certificate *models.X509Certificate
	Metadata    map[string]any
}

type SignatureSignInput struct {
	CAID             string                 `validate:"required"`
	Message          []byte                 `validate:"required"`
	MessageType      models.SignMessageType `validate:"required"`
	SigningAlgorithm string                 `validate:"required"`
}

type SignatureVerifyInput struct {
	CAID             string                 `validate:"required"`
	Signature        []byte                 `validate:"required"`
	Message          []byte                 `validate:"required"`
	MessageType      models.SignMessageType `validate:"required"`
	SigningAlgorithm string                 `validate:"required"`
}

type GetCertificatesBySerialNumberInput struct {
	SerialNumber string `validate:"required"`
}

type GetCertificatesInput struct {
	resources.ListInput[models.Certificate]
}

type GetCertificatesByCAInput struct {
	CAID string `validate:"required"`
	resources.ListInput[models.Certificate]
}

type GetCertificatesByExpirationDateInput struct {
	ExpiresAfter  time.Time
	ExpiresBefore time.Time
	resources.ListInput[models.Certificate]
}

type GetCertificatesByCaAndStatusInput struct {
	CAID   string
	Status models.CertificateStatus
	resources.ListInput[models.Certificate]
}

type GetCertificatesByStatusInput struct {
	Status models.CertificateStatus
	resources.ListInput[models.Certificate]
}

type UpdateCertificateStatusInput struct {
	SerialNumber     string                   `validate:"required"`
	NewStatus        models.CertificateStatus `validate:"required"`
	RevocationReason models.RevocationReason
}

type UpdateCertificateMetadataInput struct {
	SerialNumber string                  `validate:"required"`
	Patches      []models.PatchOperation `validate:"required"`
}
