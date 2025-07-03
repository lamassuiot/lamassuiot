package models

type IssuanceProfile struct {
	ID          string `json:"id" gorm:"primaryKey"`
	Name        string `json:"name"`
	Description string `json:"description"`

	Validity Validity `json:"validity" gorm:"embedded;embeddedPrefix:validity_"`
	SignAsCA bool     `json:"sign_as_ca"`

	HonorKeyUsage bool         `json:"honor_key_usage"`
	KeyUsage      X509KeyUsage `json:"key_usage"`

	HonorExtendedKeyUsage bool              `json:"honor_extended_key_usage"`
	ExtendedKeyUsages     []X509ExtKeyUsage `json:"extended_key_usage"`

	HonorSubject bool    `json:"honor_subject"`
	Subject      Subject `json:"subject" gorm:"embedded;embeddedPrefix:subject_"`

	HonorExtensions bool `json:"honor_extensions"`

	AllowRSAKeys   bool `json:"allow_rsa_keys"`
	AllowECDSAKeys bool `json:"allow_ecdsa_keys"`
}
