package models

import (
	"time"
)

type DeviceStatus string

const (
	DeviceNoIdentity           DeviceStatus = "NO_IDENTITY"
	DeviceActive               DeviceStatus = "ACTIVE"
	DeviceActiveWithWarns      DeviceStatus = "ACTIVE_WITH_WARNS"    //A slot should be ReEnrolled
	DeviceActiveWithCritical   DeviceStatus = "ACTIVE_WITH_CRITICAL" //A slot shas a Critical certificate and should be ReEnrolled
	DeviceActiveRequiresAction DeviceStatus = "REQUIRES_ACTION"      //A slot is revoked or expired
	DeviceDecommissioned       DeviceStatus = "DECOMMISSIONED"
)

type SlotStatus string

const (
	SlotActive             SlotStatus = "ACTIVE"
	SlotWarnExpiration     SlotStatus = "WARN" //PreventiveEnroll
	SlotCriticalExpiration SlotStatus = "CRITICAL"
	SlotExpired            SlotStatus = "EXPIRED"
	SlotRevoke             SlotStatus = "REVOKED"
)

type Device struct {
	ID                string                    `json:"id" gorm:"primaryKey"`
	Tags              []string                  `json:"tags" gorm:"serializer:json"`
	Status            DeviceStatus              `json:"status"`
	Icon              string                    `json:"icon"`
	IconColor         string                    `json:"icon_color"`
	CreationTimestamp time.Time                 `json:"creation_timestamp"`
	Metadata          map[string]any            `json:"metadata" gorm:"serializer:json"`
	DMSOwnerID        string                    `json:"dms_owner"`
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
	EvenType          DeviceEventType `json:"type"`
	EventDescriptions string          `json:"description"`
}

type DevicesStats struct {
	TotalDevices  int                  `json:"total"`
	DevicesStatus map[DeviceStatus]int `json:"status_distribution"`
}
