package models

import "time"

type IssuanceProfile struct {
	ID          string `json:"id" gorm:"primaryKey"`
	Name        string `json:"name"`
	Description string `json:"description"`

	Validity Validity `json:"validity" gorm:"embedded;embeddedPrefix:validity_"`
	SignAsCA bool     `json:"sign_as_ca"`

	// NotBefore, when non-nil, overrides the certificate's notBefore (validity
	// start) at issuance time instead of using time.Now(). It is a transient
	// issuance-time override that is NOT persisted (gorm:"-"): CMP
	// cross-certification (ccr/ccp) uses it to honour the requested CertTemplate
	// validity start. When nil, issuance uses time.Now() as before.
	NotBefore *time.Time `json:"not_before,omitempty" gorm:"-"`

	HonorKeyUsage bool         `json:"honor_key_usage"`
	KeyUsage      X509KeyUsage `json:"key_usage" gorm:"type:text;serializer:json"`

	HonorExtendedKeyUsages bool              `json:"honor_extended_key_usages"`
	ExtendedKeyUsages      []X509ExtKeyUsage `json:"extended_key_usages" gorm:"type:text;serializer:json"`
	// ExtraExtendedKeyUsageOIDs carries extendedKeyUsage purposes that have no
	// Go x509.ExtKeyUsage constant (e.g. id-kp-cmKGA 1.3.6.1.5.5.7.3.32 used for
	// RFC 9483 §4.1.6 central key generation). Each entry is a dotted OID string;
	// they are emitted into the certificate's UnknownExtKeyUsage alongside the
	// mapped ExtendedKeyUsages. Empty for ordinary profiles.
	ExtraExtendedKeyUsageOIDs []string `json:"extra_extended_key_usage_oids,omitempty" gorm:"type:text;serializer:json"`

	HonorSubject bool    `json:"honor_subject"`
	Subject      Subject `json:"subject" gorm:"embedded;embeddedPrefix:subject_"`

	HonorExtensions bool `json:"honor_extensions"`

	CryptoEnforcement IssuanceProfileCryptoEnforcement `json:"crypto_enforcement" gorm:"embedded;embeddedPrefix:crypto_enforcement_"`
}

type IssuanceProfileCryptoEnforcement struct {
	Enabled              bool  `json:"enabled"`
	AllowRSAKeys         bool  `json:"allow_rsa_keys"`
	AllowedRSAKeySizes   []int `json:"allowed_rsa_key_sizes" gorm:"type:text;serializer:json"`
	AllowECDSAKeys       bool  `json:"allow_ecdsa_keys"`
	AllowedECDSAKeySizes []int `json:"allowed_ecdsa_key_sizes" gorm:"type:text;serializer:json"`
}
