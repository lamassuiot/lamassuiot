package models

import "time"

type EventOutboxStatus string

const (
	EventOutboxPending   EventOutboxStatus = "PENDING"
	EventOutboxPublished EventOutboxStatus = "PUBLISHED"
	EventOutboxFailed    EventOutboxStatus = "FAILED"
)

type EventOutboxRecord struct {
	EventID        string            `json:"event_id" gorm:"primaryKey"`
	TenantID       string            `json:"tenant_id" gorm:"index;not null"`
	OrganizationID string            `json:"organization_id" gorm:"index;not null"`
	CorrelationID  string            `json:"correlation_id" gorm:"index;not null"`
	Type           string            `json:"type" gorm:"not null"`
	Version        string            `json:"version" gorm:"not null"`
	Payload        []byte            `json:"payload" gorm:"type:jsonb;not null"`
	Status         EventOutboxStatus `json:"status" gorm:"index;not null"`
	Attempts       int               `json:"attempts" gorm:"not null"`
	AvailableAt    time.Time         `json:"available_at" gorm:"index;not null"`
	LastError      string            `json:"last_error,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
	PublishedAt    *time.Time        `json:"published_at,omitempty"`
}

func (EventOutboxRecord) TableName() string {
	return "event_outbox"
}
