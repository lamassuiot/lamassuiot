package models

import (
	"time"
)

type CAType string

const (
	CATypeInternal CAType = "INTERNAL"
	CATypePKI      CAType = "PKI"
)

type CertificateStatus string

const (
	StatusActive             CertificateStatus = "ACTIVE"
	StatusExpired            CertificateStatus = "EXPIRED"
	StatusRevoked            CertificateStatus = "REVOKED"
	StatusNearingExpiration  CertificateStatus = "NEARING_EXPIRATION"
	StatusCriticalExpiration CertificateStatus = "CRITICAL_EXPIRATION"
)

type Certificate struct {
	Kind                string              `json:"kind" default:"v1/Certificate"`
	Rev                 string              `json:"_rev,omitempty"`
	IssuerCAMetadata    IssuerCAMetadata    `json:"issuer_metadata"`
	Status              CertificateStatus   `json:"status"`
	Fingerprint         string              `json:"fingerprint"`
	Certificate         *X509Certificate    `json:"certificate"`
	SerialNumber        string              `json:"serial_number"`
	KeyMetadata         KeyStrengthMetadata `json:"key_metadata"`
	Subject             Subject             `json:"subject"`
	ValidFrom           time.Time           `json:"valid_from"`
	ValidTo             time.Time           `json:"valid_to"`
	RevocationTimestamp time.Time           `json:"revocation_timestamp"`
	RevocationReason    string              `json:"revocation_reason"`
	Level               int                 `json:"level"`
}

type CAMetadata struct {
	EngineProviderID string `json:"engine_provider"`
	Name             string `json:"name"`
	Type             string `json:"type"`
}

type IssuerCAMetadata struct {
	EngineProviderID string `json:"engine_provider"`
	SerialNumber     string `json:"serial_number"`
	ID               string `json:"id"`
}

type CACertificate struct {
	Certificate
	Rev              string         `json:"_rev,omitempty"`
	ID               string         `json:"id"`
	Kind             string         `json:"kind" default:"v1/CACertificate"`
	Version          int            `json:"version"`
	IssuanceDuration TimeDuration   `json:"issuance_duration"`
	Metadata         CAMetadata     `json:"metadata"`
	VersionHistory   map[int]string `json:"version_history"`
	CreationTS       time.Time      `json:"creation_ts"`
}
