package resources

import (
	"time"

	"github.com/lamassuiot/lamassuiot/v2/core/pkg/models"
	cmodels "github.com/lamassuiot/lamassuiot/v2/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/resources"
)

var CAFiltrableFields = map[string]resources.FilterFieldType{
	"id":                   resources.StringFilterFieldType,
	"level":                resources.NumberFilterFieldType,
	"type":                 resources.EnumFilterFieldType,
	"serial_number":        resources.StringFilterFieldType,
	"status":               resources.EnumFilterFieldType,
	"engine_id":            resources.StringFilterFieldType,
	"valid_to":             resources.DateFilterFieldType,
	"valid_from":           resources.DateFilterFieldType,
	"revocation_timestamp": resources.DateFilterFieldType,
	"revocation_reason":    resources.EnumFilterFieldType,
	"subject.common_name":  resources.StringFilterFieldType,
}

type CreateCABody struct {
	ID                 string              `json:"id"`
	ParentID           string              `json:"parent_id"`
	Subject            cmodels.Subject     `json:"subject"`
	KeyMetadata        cmodels.KeyMetadata `json:"key_metadata"`
	CAExpiration       models.Expiration   `json:"ca_expiration"`
	IssuanceExpiration models.Expiration   `json:"issuance_expiration"`
	EngineID           string              `json:"engine_id"`
	Metadata           map[string]any      `json:"metadata"`
}

type ImportCABody struct {
	ID                 string                    `json:"id"`
	EngineID           string                    `json:"engine_id"`
	ParentID           string                    `json:"parent_id"`
	CAPrivateKey       string                    `json:"private_key"` //b64 from PEM
	CACertificate      *models.X509Certificate   `json:"ca"`
	CAChain            []*models.X509Certificate `json:"ca_chain"`
	CAType             models.CertificateType    `json:"ca_type"`
	IssuanceExpiration models.Expiration         `json:"issuance_expiration"`
}

type UpdateCAMetadataBody struct {
	Metadata map[string]interface{} `json:"metadata"`
}
type UpdateCAIssuanceExpirationBody struct {
	models.Expiration
}

type SignCertificateBody struct {
	SignVerbatim bool                           `json:"sign_verbatim"`
	CertRequest  *models.X509CertificateRequest `json:"csr"`
	Subject      *cmodels.Subject               `json:"subject"`
}

type SignatureSignBody struct {
	Message          string                 `json:"message"`
	MessageType      models.SignMessageType `json:"message_type"`
	SigningAlgorithm string                 `json:"signature_algorithm"`
}

type SignatureVerifyBody struct {
	Signature        string                 `json:"signature"`
	Message          string                 `json:"message"`
	MessageType      models.SignMessageType `json:"message_type"`
	SigningAlgorithm string                 `json:"signature_algorithm"`
}

type UpdateCertificateStatusBody struct {
	NewStatus        models.CertificateStatus `json:"status"`
	RevocationReason models.RevocationReason  `json:"revocation_reason"`
}

type UpdateCertificateMetadataBody struct {
	Metadata map[string]interface{} `json:"metadata"`
}

type GetCertificatesByExpirationDateQueryParams struct {
	ExpiresAfter  time.Time `form:"expires_after"`
	ExpiresBefore time.Time `form:"expires_before"`
}

// La estructura necesaria para la llamada

type GetCertificateStatus struct {
	CAID      string                   `json:"CAID"`
	Status    models.CertificateStatus `json:"status"`
	ListInput []models.Certificate     `json:"lostCertificates"`
}

type ImportCertificateBody struct {
	Metadata    map[string]interface{}  `json:"metadata"`
	Certificate *models.X509Certificate `json:"certificate"`
}
