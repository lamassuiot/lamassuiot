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

type SlotStatus string

const (
	SlotActive        SlotStatus = "ACTIVE"
	SlotRenewalWindow SlotStatus = "RENEWAL_PENDING" //PreventiveEnroll
	SlotAboutToExpire SlotStatus = "EXPIRING_SOON"
	SlotExpired       SlotStatus = "EXPIRED"
	SlotRevoke        SlotStatus = "REVOKED"
)

type Device struct {
	ID                string                    `json:"id" gorm:"primaryKey"`
	Tags              []string                  `json:"tags" gorm:"serializer:json"`
	Status            DeviceStatus              `json:"status"`
	Icon              string                    `json:"icon"`
	IconColor         string                    `json:"icon_color"`
	CreationTimestamp time.Time                 `json:"creation_timestamp"`
	Metadata          map[string]any            `json:"metadata" gorm:"serializer:json"`
	DMSOwner          string                    `json:"dms_owner"`
	IdentitySlot      *Slot[string]             `json:"identity,omitempty" gorm:"serializer:json"`
	ExtraSlots        map[string]*Slot[any]     `json:"slots" gorm:"serializer:json"`
	Events            map[time.Time]DeviceEvent `json:"events" gorm:"serializer:json"`
}

type Slot[E any] struct {
	Status        SlotStatus                `json:"status"`
	ActiveVersion int                       `json:"active_version"`
	SecretType    CryptoSecretType          `json:"type"`
	Secrets       map[int]E                 `json:"versions"` // version -> secret
	Events        map[time.Time]DeviceEvent `json:"events" gorm:"serializer:json"`
}

type DeviceEventType string

const (
	DeviceEventTypeCreated              DeviceEventType = "CREATED"
	DeviceEventTypeProvisioned          DeviceEventType = "PROVISIONED"
	DeviceEventTypeReProvisioned        DeviceEventType = "RE-PROVISIONED"
	DeviceEventTypeRenewed              DeviceEventType = "RENEWED"
	DeviceEventTypeShadowUpdated        DeviceEventType = "SHADOW-UPDATED"
	DeviceEventTypeStatusUpdated        DeviceEventType = "STATUS-UPDATED"
	DeviceEventTypeStatusDecommissioned DeviceEventType = "DECOMMISSIONED"
)

type DeviceEvent struct {
	EventType          DeviceEventType `json:"type"`
	EventDescriptions string          `json:"description"`
}

type DevicesStats struct {
	TotalDevices  int                  `json:"total"`
	DevicesStatus map[DeviceStatus]int `json:"status_distribution"`
}
