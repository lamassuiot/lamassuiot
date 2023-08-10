package models

import (
	"time"
)

type CAType string

const (
	CATypeManaged  CAType = "MANAGED"
	CATypeImported CAType = "IMPORTED"
	CATypeExternal CAType = "EXTERNAL"
)

type InternalCA string

const (
	CALocalRA InternalCA = "lms.lra"
)

type ExpirationTimeRef string

var (
	Duration ExpirationTimeRef = "Duration"
	Time     ExpirationTimeRef = "Time"
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
	Metadata            map[string]interface{} `json:"metadata" gorm:"serializer:json"`
	IssuerCAMetadata    IssuerCAMetadata       `json:"issuer_metadata"  gorm:"embedded;embeddedPrefix:issuer_meta_"`
	Status              CertificateStatus      `json:"status"`
	Fingerprint         string                 `json:"fingerprint"`
	Certificate         *X509Certificate       `json:"certificate"`
	SerialNumber        string                 `json:"serial_number"`
	KeyMetadata         KeyStrengthMetadata    `json:"key_metadata" gorm:"embedded;embeddedPrefix:key_strength_meta_"`
	Subject             Subject                `json:"subject" gorm:"embedded;embeddedPrefix:subject_"`
	ValidFrom           time.Time              `json:"valid_from"`
	ValidTo             time.Time              `json:"valid_to"`
	RevocationTimestamp time.Time              `json:"revocation_timestamp"`
}

type Expiration struct {
	Type     ExpirationTimeRef `json:"type"`
	Duration *TimeDuration     `json:"duration,omitempty"`
	Time     *time.Time        `json:"time,omitempty"`
}

type IssuerCAMetadata struct {
	SerialNumber string `json:"serial_number"`
	CAID         string `json:"ca_name"`
}

type CACertificate struct {
	Certificate
	ID                    string                 `json:"id" gorm:"primaryKey"`
	Metadata              map[string]interface{} `json:"metadata" gorm:"serializer:json"`
	IssuanceExpirationRef Expiration             `json:"issuance_expiration" gorm:"serializer:json"`
	Type                  CAType                 `json:"type"`
	CreationTS            time.Time              `json:"creation_ts"`
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
