package models

import (
	"time"
)

type VARole struct {
	CASubjectKeyID string        `json:"ca_ski" gorm:"column:ca_ski;"`
	CRLOptions     VACRLRole     `json:"crl_options" gorm:"embedded;embeddedPrefix:crl_"`
	LatestCRL      LatestCRLMeta `json:"latest_crl" gorm:"embedded;embeddedPrefix:latest_crl_"`
}

type VACRLRole struct {
	RefreshInterval               TimeDuration `json:"refresh_interval" gorm:"serializer:text"`
	Validity                      TimeDuration `json:"validity" gorm:"serializer:text"`
	SignerCertificateSerialNumber string       `json:"signer_certificate_serial_number" validate:"required"`
	RegenerateOnRevoke            bool         `json:"regenerate_on_revoke"`
}
type LatestCRLMeta struct {
	Version    BigInt    `json:"version" gorm:"type:NUMERIC;serializer:text"`
	ValidFrom  time.Time `json:"valid_from"`
	ValidUntil time.Time `json:"valid_until"`
}
