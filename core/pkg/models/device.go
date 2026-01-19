package models

import (
	"time"
)

type DeviceStatusType string

const (
	DeviceStatusOK             DeviceStatusType = "OK"
	DeviceStatusWarn           DeviceStatusType = "WARN"
	DeviceStatusError          DeviceStatusType = "ERROR"
	DeviceStatusDecommissioned DeviceStatusType = "DECOMMISSIONED"
)

type Device struct {
	ID                string                `json:"id" gorm:"primaryKey"`
	Tags              []string              `json:"tags" gorm:"serializer:json"`
	Status            DeviceStatusType      `json:"status"`
	Icon              string                `json:"icon"`
	IconColor         string                `json:"icon_color"`
	CreationTimestamp time.Time             `json:"creation_timestamp"`
	Metadata          map[string]any        `json:"metadata" gorm:"serializer:json"`
	DMSOwner          string                `json:"dms_owner"`
	IdentitySlot      *Slot[string]         `json:"identity,omitempty" gorm:"serializer:json"`
	ExtraSlots        map[string]*Slot[any] `json:"slots" gorm:"serializer:json"`
}

type DevicesStats struct {
	TotalDevices  int                      `json:"total"`
	DevicesStatus map[DeviceStatusType]int `json:"status_distribution"`
}

// DeviceGroupFilterOption represents a filter criterion for dynamic device group membership.
// This is a copy of resources.FilterOption to avoid circular dependencies.
type DeviceGroupFilterOption struct {
	Field           string `json:"field"`
	FilterOperation int    `json:"operand"`
	Value           string `json:"value"`
}

type DeviceGroup struct {
	ID          string                    `json:"id" gorm:"primaryKey"`
	Name        string                    `json:"name" gorm:"uniqueIndex"`
	Description string                    `json:"description"`
	ParentID    *string                   `json:"parent_id,omitempty" gorm:"column:parent_id"`
	Criteria    []DeviceGroupFilterOption `json:"criteria" gorm:"serializer:json"`
	CreatedAt   time.Time                 `json:"created_at"`
	UpdatedAt   time.Time                 `json:"updated_at"`

	// Transient field for API response generation - not stored in DB
	OwnCriteriaCount int `json:"-" gorm:"-"`
}
