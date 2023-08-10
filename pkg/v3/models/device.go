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
	SlotWarnExpiration     SlotStatus = "WARN"
	SlotCriticalExpiration SlotStatus = "CRITICAL"
	SlotExpired            SlotStatus = "EXPIRED"
	SlotRevoke             SlotStatus = "REVOKED"
)

type Device struct {
	ID           string       `json:"id"`
	Alias        string       `json:"alias"`
	Tags         []string     `json:"tags"`
	Status       DeviceStatus `json:"status"`
	Icon         string       `json:"icon"`
	IconColor    string       `json:"icon_color"`
	CreationDate time.Time    `json:"creation_ts"`
	//Metadata set by DMS or end users
	Metadata     map[string]string     `json:"metadata"`
	DMSOwnerID   string                `json:"dms_owner"`
	IdentitySlot *Slot[Certificate]    `json:"identity,omitempty"`
	ExtraSlots   map[string]*Slot[any] `json:"slots"`
	Logs         map[time.Time]LogMsg  `json:"logs"`
}

type Slot[E any] struct {
	Status        SlotStatus           `json:"status"`
	ActiveVersion int                  `json:"active_version"`
	SecretType    CryptoSecretType     `json:"type"`
	Secrets       map[int]E            `json:"versions"` // version -> secret
	Logs          map[time.Time]LogMsg `json:"logs"`
}

type LogMsg struct {
	Msg         string         `json:"message"`
	Criticality LogCriticality `json:"Criticality"`
}

type LogCriticality string

const (
	InfoCriticality  LogCriticality = "INFO"
	ErrorCriticality LogCriticality = "ERROR"
	WarnCriticality  LogCriticality = "WARN"
)

type Criticality string

const (
	CRITICAL Criticality = "CRITICAL"
	WARN     Criticality = "WARN"
	INFO     Criticality = "INFO"
	ERROR    Criticality = "ERROR"
)

type DeviceLog struct {
	ID          string            `json:"id"`
	Message     string            `json:"message"`
	Criticality Criticality       `json:"Criticality"`
	Metadata    map[string]string `json:"metadata"`
}
