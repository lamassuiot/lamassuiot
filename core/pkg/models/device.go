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
