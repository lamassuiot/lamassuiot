package models

import (
	"time"
)

// CRLSettingsStatus is the lifecycle state of the CRL settings of a CA.
type CRLSettingsStatus string

const (
	// CRLSettingsActive settings are used to generate CRLs. The database retains the key of their signer.
	CRLSettingsActive CRLSettingsStatus = "ACTIVE"
	// CRLSettingsFinal settings belong to a revoked or expired CA: their final CRL, if any, is published and nothing
	// signs a new one, so the key of their signer is no longer retained. Their signer certificate still is.
	CRLSettingsFinal CRLSettingsStatus = "FINAL"
	// CRLSettingsArchived settings belong to a CA that no longer exists: their last CRL is still served, but never
	// regenerated, and they retain nothing.
	CRLSettingsArchived CRLSettingsStatus = "ARCHIVED"
)

// CRLSignerKey identifies the KMS key of a CRL signer certificate.
type CRLSignerKey struct {
	EngineID string
	KeyID    string
}

// CRLSettings holds how the CRL of a CA is generated and the state of its latest CRL. They are keyed by the ID of the
// CA, never by its Subject Key Identifier: CAs sharing a key share the SKI, not the CRL.
type CRLSettings struct {
	CAID string `json:"ca_id" gorm:"column:ca_id"`
	// LegacySKI is the SKI the settings were keyed by before they moved to the CA ID. Only migrated settings have one:
	// the CDP of the certificates issued back then, /crl/<ski>, keeps resolving to them.
	LegacySKI *string            `json:"legacy_ski,omitempty" gorm:"column:legacy_ski"`
	Options   CRLSettingsOptions `json:"crl_options" gorm:"embedded"`
	Status    CRLSettingsStatus  `json:"status" gorm:"column:status"`
	// SignerEngineID and SignerKeyID copy the KMS key of the signer certificate while the settings are ACTIVE, only so
	// that the database retains it in the KMS (crl_settings_signer_key_fk). They are never set by the API.
	SignerEngineID *string       `json:"-" gorm:"column:signer_engine_id"`
	SignerKeyID    *string       `json:"-" gorm:"column:signer_key_id"`
	LatestCRL      LatestCRLMeta `json:"latest_crl" gorm:"embedded;embeddedPrefix:latest_crl_"`
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
