package models

import (
	"time"
)

// CRLSettingsStatus is the lifecycle state of the CRL settings of a CA.
type CRLSettingsStatus string

const (
	// CRLSettingsActive settings are used to generate CRLs.
	CRLSettingsActive CRLSettingsStatus = "ACTIVE"
	// CRLSettingsArchived settings belong to a CA that no longer exists: their last CRL is still served, but never regenerated.
	CRLSettingsArchived CRLSettingsStatus = "ARCHIVED"
)

// CRLSettings holds how the CRL of a CA is generated and the state of its latest CRL. They are keyed by the ID of the
// CA, never by its Subject Key Identifier: CAs sharing a key share the SKI, not the CRL.
type CRLSettings struct {
	CAID string `json:"ca_id" gorm:"column:ca_id"`
	// LegacySKI is the SKI the settings were keyed by before they moved to the CA ID. Only migrated settings have one:
	// the CDP of the certificates issued back then, /crl/<ski>, keeps resolving to them.
	LegacySKI *string            `json:"legacy_ski,omitempty" gorm:"column:legacy_ski"`
	Options   CRLSettingsOptions `json:"crl_options" gorm:"embedded"`
	Status    CRLSettingsStatus  `json:"status" gorm:"column:status"`
	LatestCRL LatestCRLMeta      `json:"latest_crl" gorm:"embedded;embeddedPrefix:latest_crl_"`
}

// CRLSettingsOptions are the editable settings.
type CRLSettingsOptions struct {
	RefreshInterval    TimeDuration `json:"refresh_interval" gorm:"column:refresh_interval;serializer:text"`
	Validity           TimeDuration `json:"validity" gorm:"column:validity;serializer:text"`
	SignerSerialNumber string       `json:"signer_serial_number" gorm:"column:signer_serial_number" validate:"required"`
	RegenerateOnRevoke bool         `json:"regenerate_on_revoke" gorm:"column:regenerate_on_revoke"`
}

type LatestCRLMeta struct {
	Version    BigInt    `json:"version" gorm:"type:NUMERIC;serializer:text"`
	ValidFrom  time.Time `json:"valid_from"`
	ValidUntil time.Time `json:"valid_until"`
}
