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
	"subject_key_id":       StringFilterFieldType,
	"profile_id":           StringFilterFieldType,
}

var CARequestFiltrableFields = map[string]FilterFieldType{
	"id":                  StringFilterFieldType,
	"level":               NumberFilterFieldType,
	"status":              EnumFilterFieldType,
	"engine_id":           StringFilterFieldType,
	"subject_common_name": StringFilterFieldType,
	"issuer_metadata_id":  StringFilterFieldType,
}

var IssuanceProfileFiltrableFields = map[string]FilterFieldType{
	"id":   StringFilterFieldType,
	"name": StringFilterFieldType,
}

type CreateCABody struct {
	ID           string             `json:"id"`
	ParentID     string             `json:"parent_id"`
	Subject      models.Subject     `json:"subject"`
	KeyMetadata  models.KeyMetadata `json:"key_metadata"`
	CAExpiration models.Validity    `json:"ca_expiration"`
	ProfileID    string             `json:"profile_id"`
	EngineID     string             `json:"engine_id"`
	Metadata     map[string]any     `json:"metadata"`
}

type CreateHybridCABody struct {
	ID           string            	`json:"id"`
	ParentID     string            	`json:"parent_id"`
	Subject      models.Subject     `json:"subject"`
	OuterKeyMetadata  models.KeyMetadata `json:"outer_key_metadata"`
	InnerKeyMetadata  models.KeyMetadata `json:"inner_key_metadata"`
	CAExpiration models.Validity   	`json:"ca_expiration"`
	ProfileID    string            	`json:"profile_id"`
	EngineID     string            	`json:"engine_id"`
	Metadata     map[string]any     `json:"metadata"`
	HybridCertificateType models.HybridCertificateType `json:"hybrid_certificate_type"`
}

type RequestCABody struct {
	ID          string             `json:"id"`
	Subject     models.Subject     `json:"subject"`
	KeyMetadata models.KeyMetadata `json:"key_metadata"`
	EngineID    string             `json:"engine_id"`
	Metadata    map[string]any     `json:"metadata"`
}

type ImportCABody struct {
	ID            string                    `json:"id"`
	EngineID      string                    `json:"engine_id"`
	ParentID      string                    `json:"parent_id"`
	CARequestID   string                    `json:"ca_request_id"`
	CAPrivateKey  string                    `json:"private_key"` //b64 from PEM
	CACertificate *models.X509Certificate   `json:"ca"`
	CAChain       []*models.X509Certificate `json:"ca_chain"`
	CAType        models.CertificateType    `json:"ca_type"`
	ProfileID     string                    `json:"profile_id"`
}

type UpdateCAMetadataBody struct {
	Patches []models.PatchOperation `json:"patches"`
}

type SignCertificateBody struct {
	CertRequest *models.X509CertificateRequest `json:"csr"`
	Profile     models.IssuanceProfile         `json:"profile"`
	ProfileID   string                         `json:"profile_id"`
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

type UpdateCAProfileBody struct {
	ProfileID string `json:"profile_id" validate:"required"`
}

type UpdateCertificateMetadataBody struct {
	Patches []models.PatchOperation `validate:"required"`
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

type CreateUpdateIssuanceProfileBody struct {
	Name                   string                                     `json:"name"`
	Description            string                                     `json:"description"`
	Validity               models.Validity                            `json:"validity"`
	SignAsCA               bool                                       `json:"sign_as_ca"`
	HonorKeyUsage          bool                                       `json:"honor_key_usage"`
	KeyUsage               models.X509KeyUsage                        `json:"key_usage"`
	HonorExtendedKeyUsages bool                                       `json:"honor_extended_key_usages"`
	ExtendedKeyUsages      []models.X509ExtKeyUsage                   `json:"extended_key_usages"`
	HonorSubject           bool                                       `json:"honor_subject"`
	Subject                models.Subject                             `json:"subject"`
	HonorExtensions        bool                                       `json:"honor_extensions"`
	CryptoEnforcement      CreateIssuanceProfileCryptoEnforcementBody `json:"crypto_enforcement"`
}

type CreateIssuanceProfileCryptoEnforcementBody struct {
	Enabled              bool  `json:"enabled"`
	AllowRSAKeys         bool  `json:"allow_rsa_keys"`
	AllowedRSAKeySizes   []int `json:"allowed_rsa_key_sizes"`
	AllowECDSAKeys       bool  `json:"allow_ecdsa_keys"`
	AllowedECDSAKeySizes []int `json:"allowed_ecdsa_key_sizes"`
}
