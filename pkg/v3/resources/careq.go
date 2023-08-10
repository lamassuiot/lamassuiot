package resources

import (
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
)

type CreateCABody struct {
	Subject            models.Subject     `json:"subject"`
	KeyMetadata        models.KeyMetadata `json:"key_metadata"`
	CAType             models.CAType      `json:"ca_type"`
	CAExpiration       models.Expiration  `json:"ca_expiration"`
	IssuanceExpiration models.Expiration  `json:"issuance_expiration"`
}

type ImportCABody struct {
	CAPrivateKey       string                    `json:"private_key"` //b64 from PEM
	CACertificate      *models.X509Certificate   `json:"ca"`
	CAChain            []*models.X509Certificate `json:"ca_chain"`
	CAType             models.CAType             `json:"ca_type"`
	IssuanceExpiration models.Expiration         `json:"issuance_expiration"`
}

type UpdateCAMetadataBody struct {
	Metadata map[string]interface{} `json:"metadata"`
}

type SignCertificateBody struct {
	SignVerbatim bool                           `json:"sign_verbatim"`
	CertRequest  *models.X509CertificateRequest `json:"csr"`
	Subject      *models.Subject                `json:"subject"`
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
	NewStatus models.CertificateStatus `json:"status"`
}

type UpdateCertificateMetadataBody struct {
	Metadata map[string]interface{} `json:"metadata"`
}
