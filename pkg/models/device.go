package models

import (
	"time"
)

type DeviceStatus string

const (
	DeviceNoIdentity     DeviceStatus = "NO_IDENTITY"
	DeviceActive         DeviceStatus = "ACTIVE"
	DeviceRenewalWindow  DeviceStatus = "RENEWAL_PENDING" //A slot should be ReEnrolled
	DeviceAboutToExpire  DeviceStatus = "EXPIRING_SOON"   //A slot has a Critical certificate and should be ReEnrolled
	DeviceExpired        DeviceStatus = "EXPIRED"
	DeviceRevoked        DeviceStatus = "REVOKED"
	DeviceDecommissioned DeviceStatus = "DECOMMISSIONED"
)

type Device struct {
	ID                string                `json:"id" gorm:"primaryKey"`
	Tags              []string              `json:"tags" gorm:"serializer:json"`
	Status            DeviceStatus          `json:"status"`
	Icon              string                `json:"icon"`
	IconColor         string                `json:"icon_color"`
	CreationTimestamp time.Time             `json:"creation_timestamp"`
	Metadata          map[string]any        `json:"metadata" gorm:"serializer:json"`
	DMSOwner          string                `json:"dms_owner"`
	IdentitySlot      *Slot[string]         `json:"identity,omitempty" gorm:"serializer:json"`
	ExtraSlots        map[string]*Slot[any] `json:"slots" gorm:"serializer:json"`
}

type Slot[E any] struct {
	ActiveVersion int              `json:"active_version"`
	SecretType    CryptoSecretType `json:"type"`
	Secrets       map[int]E        `json:"versions"` // version -> secret
}

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

type DevicesStats struct {
	TotalDevices  int                  `json:"total"`
	DevicesStatus map[DeviceStatus]int `json:"status_distribution"`
}
