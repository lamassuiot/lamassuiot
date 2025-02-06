package resources

import (
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

var CAFiltrableFields = map[string]FilterFieldType{
	"id":                   StringFilterFieldType,
	"level":                NumberFilterFieldType,
	"type":                 EnumFilterFieldType,
	"serial_number":        StringFilterFieldType,
	"status":               EnumFilterFieldType,
	"engine_id":            StringFilterFieldType,
	"valid_to":             DateFilterFieldType,
	"valid_from":           DateFilterFieldType,
	"revocation_timestamp": DateFilterFieldType,
	"revocation_reason":    EnumFilterFieldType,
	"subject.common_name":  StringFilterFieldType,
	"key_id":               StringFilterFieldType,
}

var CARequestFiltrableFields = map[string]FilterFieldType{
	"id":                  StringFilterFieldType,
	"level":               NumberFilterFieldType,
	"status":              EnumFilterFieldType,
	"engine_id":           StringFilterFieldType,
	"subject_common_name": StringFilterFieldType,
	"issuer_metadata_id":  StringFilterFieldType,
}

type CreateCABody struct {
	ID                 string             `json:"id"`
	ParentID           string             `json:"parent_id"`
	Subject            models.Subject     `json:"subject"`
	KeyMetadata        models.KeyMetadata `json:"key_metadata"`
	CAExpiration       models.Validity    `json:"ca_expiration"`
	IssuanceExpiration models.Validity    `json:"issuance_expiration"`
	EngineID           string             `json:"engine_id"`
	Metadata           map[string]any     `json:"metadata"`
}

type RequestCABody struct {
	ID          string             `json:"id"`
	Subject     models.Subject     `json:"subject"`
	KeyMetadata models.KeyMetadata `json:"key_metadata"`
	EngineID    string             `json:"engine_id"`
	Metadata    map[string]any     `json:"metadata"`
}

type ImportCABody struct {
	ID                 string                    `json:"id"`
	EngineID           string                    `json:"engine_id"`
	ParentID           string                    `json:"parent_id"`
	CARequestID        string                    `json:"ca_request_id"`
	CAPrivateKey       string                    `json:"private_key"` //b64 from PEM
	CACertificate      *models.X509Certificate   `json:"ca"`
	CAChain            []*models.X509Certificate `json:"ca_chain"`
	CAType             models.CertificateType    `json:"ca_type"`
	IssuanceExpiration models.Validity           `json:"issuance_expiration"`
}

type UpdateCAMetadataBody struct {
	Metadata map[string]interface{} `json:"metadata"`
}
type UpdateCAIssuanceExpirationBody struct {
	models.Validity
}

type SignCertificateBody struct {
	CertRequest *models.X509CertificateRequest `json:"csr"`
	Profile     models.IssuanceProfile         `json:"profile"`
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
