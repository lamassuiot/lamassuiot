package resources

import (
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
)

type CreateCABody struct {
	Subject            models.Subject      `json:"subject"`
	KeyMetadata        models.KeyMetadata  `json:"key_metadata"`
	CAType             models.CAType       `json:"ca_type"`
	IssuanceDuration   models.TimeDuration `json:"issuance_duration"`
	CAVailidtyDurarion models.TimeDuration `json:"ca_duration"`
}

type ImportCABody struct {
	CAPrivateKey     string                    `json:"private_key"` //b64 from PEM
	CACertificate    *models.X509Certificate   `json:"ca"`
	CAChain          []*models.X509Certificate `json:"ca_chain"`
	CAType           models.CAType             `json:"ca_type"`
	IssuanceDuration models.TimeDuration       `json:"issuance_duration"`
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

type SignCertificateBody struct {
	SignVerbatim bool                           `json:"sign_verbatim"`
	CertRequest  *models.X509CertificateRequest `json:"csr"`
	Subject      models.Subject                 `json:"subject"`
}

type UpdateCertificateStatusBody struct {
	NewStatus models.CertificateStatus `json:"status"`
}
