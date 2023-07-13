package resources

import (
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
)

type CreateCABody struct {
	Subject            models.Subject     `json:"subject"`
	KeyMetadata        models.KeyMetadata `json:"key_metadata"`
	CAType             models.CAType      `json:"ca_type"`
	CAExpitration      models.Expiration  `json:"ca_expiration"`
	IssuanceExpiration models.Expiration  `json:"issuance_expiration"`
}

type ImportCABody struct {
	CAPrivateKey       string                    `json:"private_key"` //b64 from PEM
	CACertificate      *models.X509Certificate   `json:"ca"`
	CAChain            []*models.X509Certificate `json:"ca_chain"`
	CAType             models.CAType             `json:"ca_type"`
	IssuanceExpiration models.Expiration         `json:"issuance_expiration"`
}

type SignBody struct {
	Message            string                    `json:"message"` //b64
	MessageType        models.SigningMessageType `json:"message_type"`
	SignatureAlgorithm models.SigningAlgorithm   `json:"signature_algorithm"`
}

type VerifyBody struct {
	Message            string                    `json:"message"` //b64
	MessageType        models.SigningMessageType `json:"message_type"`
	SignatureAlgorithm models.SigningAlgorithm   `json:"signature_algorithm"`
	Signature          string                    `json:"signature"` //b64
}

type UpdateCAMetadataBody struct {
	Metadata map[string]interface{} `json:"metadata"`
}

type SignCertificateBody struct {
	SignVerbatim bool                           `json:"sign_verbatim"`
	CertRequest  *models.X509CertificateRequest `json:"csr"`
	Subject      models.Subject                 `json:"subject"`
}

type UpdateCertificateStatusBody struct {
	NewStatus models.CertificateStatus `json:"status"`
}

type UpdateCertificateMetadataBody struct {
	Metadata map[string]interface{} `json:"metadata"`
}
