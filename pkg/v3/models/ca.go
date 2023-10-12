package models

import (
	"time"
)

type CertificateType string

const (
	CertificateTypeManaged  CertificateType = "MANAGED"
	CertificateTypeImported CertificateType = "IMPORTED"
	CertificateTypeExternal CertificateType = "EXTERNAL"
)

type ExpirationTimeRef string

var (
	Duration ExpirationTimeRef = "Duration"
	Time     ExpirationTimeRef = "Time"
)

type CertificateStatus string

const (
	StatusActive  CertificateStatus = "ACTIVE"
	StatusExpired CertificateStatus = "EXPIRED"
	StatusRevoked CertificateStatus = "REVOKED"
)

type Certificate struct {
	SerialNumber        string                 `json:"serial_number" gorm:"primaryKey"`
	Metadata            map[string]interface{} `json:"metadata" gorm:"serializer:json"`
	IssuerCAMetadata    IssuerCAMetadata       `json:"issuer_metadata"  gorm:"embedded;embeddedPrefix:issuer_meta_"`
	Status              CertificateStatus      `json:"status"`
	Certificate         *X509Certificate       `json:"certificate"`
	KeyMetadata         KeyStrengthMetadata    `json:"key_metadata" gorm:"embedded;embeddedPrefix:key_strength_meta_"`
	Subject             Subject                `json:"subject" gorm:"embedded;embeddedPrefix:subject_"`
	ValidFrom           time.Time              `json:"valid_from"`
	ValidTo             time.Time              `json:"valid_to"`
	RevocationTimestamp time.Time              `json:"revocation_timestamp"`
	RevocationReason    RevocationReason       `json:"revocation_reason"`
	Type                CertificateType        `json:"type"`
	EngineID            string                 `json:"engine_id"`
}

type Expiration struct {
	Type     ExpirationTimeRef `json:"type"`
	Duration *TimeDuration     `json:"duration,omitempty"`
	Time     *time.Time        `json:"time,omitempty"`
}

type IssuerCAMetadata struct {
	SerialNumber string `json:"serial_number"`
	CAID         string `json:"ca_id"`
}

type CACertificate struct {
	Certificate
	ID                    string                 `json:"id" gorm:"primaryKey"`
	Metadata              map[string]interface{} `json:"metadata" gorm:"serializer:json"`
	IssuanceExpirationRef Expiration             `json:"issuance_expiration" gorm:"serializer:json"`
	Type                  CertificateType        `json:"type"`
	CreationTS            time.Time              `json:"creation_ts"`
}

type CAStats struct {
	CACertificatesStats CACertificatesStats `json:"cas"`
	CertificatesStats   CertificatesStats   `json:"certificates"`
}
type CACertificatesStats struct {
	TotalCAs                 int                       `json:"total"`
	CAsDistributionPerEngine map[string]int            `json:"engine_distribution"`
	CAsStatus                map[CertificateStatus]int `json:"status_distribution"`
}
type CertificatesStats struct {
	TotalCertificates            int                       `json:"total"`
	CertificateDistributionPerCA map[string]int            `json:"ca_distribution"`
	CertificateStatus            map[CertificateStatus]int `json:"status_distribution"`
}

type MonitoringExpirationDelta struct {
	Delta     TimeDuration `json:"delta"`
	Name      string       `json:"name"`
	Triggered bool         `json:"triggered"`
}

const (
	CAMetadataMonitoringExpirationDeltasKey = "lamassu.io/ca/expiration-deltas"
)

type CAMetadataMonitoringExpirationDeltas []MonitoringExpirationDelta
