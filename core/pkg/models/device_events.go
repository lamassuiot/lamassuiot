package models

import "time"

type DeviceEventType string

const DeviceEventTypeShadowUpdated DeviceEventType = "lamassu.io/device-event/idslot/shadow/update"
const DeviceEventTypeLifecycleStatusUpdated DeviceEventType = "lamassu.io/device-event/lifecycle/status/update"

type DeviceEventTypeIDSlotStates string

const (
	DeviceEventTypeIDSlotStatusUpdated            DeviceEventType             = "lamassu.io/device-event/idslot/status/update"
	DeviceEventTypeIDSlotStatusStateProvisioned   DeviceEventTypeIDSlotStates = "PROVISIONED"
	DeviceEventTypeIDSlotStatusStateReProvisioned DeviceEventTypeIDSlotStates = "RE-PROVISIONED"
	DeviceEventTypeIDSlotStatusStateRenewed       DeviceEventTypeIDSlotStates = "RENEWED"
)

type DeviceEvent struct {
	Timestamp       time.Time `json:"timestamp"`
	DeviceID        string    `json:"device_id"`
	Type            string    `json:"type"`
	Message         string    `json:"message"`
	SlotID          string    `json:"slot_id,omitempty"`
	Source          string    `json:"source,omitempty"`
	StructuredField any       `json:"structured_field,omitempty"`
}

type DeviceStatus struct {
	DeviceID   string           `json:"device_id"`
	Status     DeviceStatusType `json:"status"`
	UpdateTime time.Time        `json:"update_time"`
}
