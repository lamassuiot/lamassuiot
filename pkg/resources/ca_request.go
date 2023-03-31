package resources

import (
	"github.com/lamassuiot/lamassuiot/pkg/models"
)

type CreateCABody struct {
	Subject            models.Subject      `json:"subject"`
	KeyMetadata        models.KeyMetadata  `json:"key_metadata"`
	CAType             models.CAType       `json:"ca_type"`
	IssuerCAID         string              `json:"issuer_ca_id"`
	IssuanceDuration   models.TimeDuration `json:"issuance_duration"`
	CAVailidtyDurarion models.TimeDuration `json:"ca_duration"`
	EngineID           string              `json:"engine_id"`
}

type ImportCABody struct {
	EngineID         string                    `json:"engine_id"`
	CAPrivateKey     string                    `json:"private_key"` //b64 from PEM
	CACertificate    *models.X509Certificate   `json:"ca"`
	CAChain          []*models.X509Certificate `json:"ca_chain"`
	CAType           models.CAType             `json:"ca_type"`
	IssuanceDuration models.TimeDuration       `json:"issuance_duration"`
}

type SignCertificateBody struct {
	SignVerbatim bool                           `json:"sign_verbatim"`
	CertRequest  *models.X509CertificateRequest `json:"csr"`
	Subject      models.Subject                 `json:"subject"`
}
