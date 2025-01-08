package models

import "time"

type DeviceEventType string

const (
	DeviceEventTypeCreated              DeviceEventType = "CREATED"
	DeviceEventTypeProvisioned          DeviceEventType = "PROVISIONED"
	DeviceEventTypeReProvisioned        DeviceEventType = "RE-PROVISIONED"
	DeviceEventTypeRenewed              DeviceEventType = "RENEWED"
	DeviceEventTypeShadowUpdated        DeviceEventType = "SHADOW-UPDATED"
	DeviceEventTypeConnectionUpdate     DeviceEventType = "CONNECTION-UPDATED"
	DeviceEventTypeStatusUpdated        DeviceEventType = "STATUS-UPDATED"
	DeviceEventTypeStatusDecommissioned DeviceEventType = "DECOMMISSIONED"
)

type DeviceEvent struct {
	ID               string          `json:"id" gorm:"primaryKey"`
	DeviceID         string          `json:"device_id"`
	Timestamp        time.Time       `json:"timestamp"`
	Type             DeviceEventType `json:"type"`
	Description      string          `json:"description"`
	Source           string          `json:"source"`
	Status           DeviceStatus    `json:"status"`
	StructuredFields map[string]any  `json:"structured_fields" gorm:"serializer:json"`
}
