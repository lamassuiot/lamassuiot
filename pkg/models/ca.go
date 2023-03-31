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
	Type             CAType `json:"type"`
}

type IssuerCAMetadata struct {
	EngineProviderID string `json:"engine_provider"`
	SerialNumber     string `json:"serial_number"`
	ID               string `json:"id"`
}

type CACertificate struct {
	Certificate
	ID               string         `json:"id"`
	External         bool           `json:"external"`
	Version          int            `json:"version"`
	IssuanceDuration TimeDuration   `json:"issuance_duration"`
	Metadata         CAMetadata     `json:"metadata"`
	VersionHistory   map[int]string `json:"version_history"`
	CreationTS       time.Time      `json:"creation_ts"`
}

type CAStats struct {
	CACertificatesStats struct {
		TotalCAs                 int                       `json:"total"`
		CAsDistributionPerEngine map[string]int            `json:"engine_distribution"`
		CAsStatus                map[CertificateStatus]int `json:"status_distribution"`
	} `json:"cas"`
	CertificatesStats struct {
		TotalCertificates            int                       `json:"total"`
		CertificateDistributionPerCA map[string]int            `json:"ca_distribution"`
		CertificateStatus            map[CertificateStatus]int `json:"status_distribution"`
	} `json:"certificates"`
}
