package models

import (
	"time"
)

type CertificateType string

const (
	CertificateTypeManaged         CertificateType = "MANAGED"
	CertificateTypeRequested       CertificateType = "REQUESTED"
	CertificateTypeImportedWithKey CertificateType = "IMPORTED"
	CertificateTypeExternal        CertificateType = "EXTERNAL"
)

type ValidityType string

var (
	Duration ValidityType = "Duration"
	Time     ValidityType = "Time"
)

type CertificateStatus string

const (
	StatusActive   CertificateStatus = "ACTIVE"
	StatusExpired  CertificateStatus = "EXPIRED"
	StatusRevoked  CertificateStatus = "REVOKED"
	StatusInactive CertificateStatus = "INACTIVE"
)

type Certificate struct {
	SerialNumber        string                 `json:"serial_number" gorm:"primaryKey"`
	KeyID               string                 `json:"key_id"`
	Metadata            map[string]interface{} `json:"metadata" gorm:"serializer:json"`
	Status              CertificateStatus      `json:"status"`
	Certificate         *X509Certificate       `json:"certificate"`
	KeyMetadata         KeyStrengthMetadata    `json:"key_metadata" gorm:"embedded;embeddedPrefix:key_meta_"`
	Subject             Subject                `json:"subject" gorm:"embedded;embeddedPrefix:subject_"`
	ValidFrom           time.Time              `json:"valid_from"`
	IssuerCAMetadata    IssuerCAMetadata       `json:"issuer_metadata" gorm:"embedded;embeddedPrefix:issuer_meta_"`
	ValidTo             time.Time              `json:"valid_to"`
	RevocationTimestamp time.Time              `json:"revocation_timestamp"`
	RevocationReason    RevocationReason       `json:"revocation_reason" gorm:"serializer:text"`
	Type                CertificateType        `json:"type"`
	EngineID            string                 `json:"engine_id"`
	IsCA                bool                   `json:"is_ca"`
}

type Validity struct {
	Type     ValidityType `json:"type"`
	Duration TimeDuration `json:"duration,omitempty" gorm:"serializer:text"`
	Time     time.Time    `json:"time"`
}

type IssuerCAMetadata struct {
	SN    string `json:"serial_number" gorm:"column:serial_number"`
	ID    string `json:"id"`
	Level int    `json:"level"`
}

type CACertificate struct {
	ID                      string                 `json:"id"`
	Certificate             Certificate            `json:"certificate" gorm:"foreignKey:CertificateSerialNumber;references:SerialNumber"`
	CertificateSerialNumber string                 `json:"serial_number" gorm:"column:serial_number"`
	Metadata                map[string]interface{} `json:"metadata" gorm:"serializer:json"`
	Validity                Validity               `json:"validity" gorm:"embedded;embeddedPrefix:validity_"`
	CreationTS              time.Time              `json:"creation_ts"`
	Level                   int                    `json:"level"`
}

type CertificateRequestStatus string

const (
	StatusRequestIssued  CertificateRequestStatus = "ISSUED"
	StatusRequestRevoked CertificateRequestStatus = "REVOKED"
	StatusRequestPending CertificateRequestStatus = "PENDING"
)

type CACertificateRequest struct {
	ID          string                   `json:"id"`
	KeyId       string                   `json:"key_id"`
	Metadata    map[string]interface{}   `json:"metadata" gorm:"serializer:json"`
	Subject     Subject                  `json:"subject" gorm:"embedded;embeddedPrefix:subject_"`
	CreationTS  time.Time                `json:"creation_ts"`
	EngineID    string                   `json:"engine_id"`
	KeyMetadata KeyStrengthMetadata      `json:"key_metadata" gorm:"embedded;embeddedPrefix:key_meta_"`
	Status      CertificateRequestStatus `json:"status"`
	Fingerprint string                   `json:"fingerprint"`
	CSR         X509CertificateRequest   `json:"csr"`
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

const (
	CAAttachedToDeviceKey = "lamassu.io/ca/attached-to"
)

type CAAttachedToDevice struct {
	AuthorizedBy struct {
		RAID string `json:"ra_id"`
	} `json:"authorized_by"`
	DeviceID string `json:"device_id"`
}
