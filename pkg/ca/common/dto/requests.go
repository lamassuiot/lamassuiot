package dto

type CreateCARequestPayload struct {
	KeyMetadata PrivateKeyMetadata `json:"key_metadata" validate:"required"`

	Subject Subject `json:"subject"`

	CaTTL       int `json:"ca_ttl" validate:"required"`
	EnrollerTTL int `json:"enroller_ttl" validate:"gt=0"`
}

type ImportCARequestPayload struct {
	EnrollerTTL int    `json:"enroller_ttl" validate:"required"`
	Crt         string `json:"crt" validate:"base64"`
	PrivateKey  string `json:"private_key" validate:"base64"`
}

type SignPayload struct {
	Csr          string `json:"csr" validate:"base64"`
	CommonName   string `json:"cn"`
	SignVerbatim bool   `json:"sign_verbatim"`
}
