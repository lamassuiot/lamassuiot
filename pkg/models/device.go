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
	DeviceDecommissioned       DeviceStatus = "DECOMMISIONED"
)

type SlotStatus string

const (
	SlotActive   SlotStatus = "ACTIVE"
	SlotWarn     SlotStatus = "WARN"
	SlotCritical SlotStatus = "CRITICAL"
	SlotExpired  SlotStatus = "EXPIRED"
	SlotRevoke   SlotStatus = "REVOKED"
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
	Metadata map[string]string `json:"metadata"`
	//Metadata collected by the server when a device tries to connect (ie. User Agent, Remote Address)
	ConnectionMetadata map[string]string     `json:"connection_metadata"`
	DMSOwnerID         string                `json:"dms_owner"`
	IdentitySlot       *Slot[Certificate]    `json:"identity,omitempty"`
	ExtraSlots         map[string]*Slot[any] `json:"slots"`
	Logs               map[time.Time]LogMsg  `json:"logs"`
}

type Slot[E any] struct {
	DMSManaged                  bool                 `json:"dms_managed"` //if true, the certificate MUST be obtained from the DMS server
	Status                      SlotStatus           `json:"status"`
	ActiveVersion               int                  `json:"active_version"`
	AllowedReenrollmentDelta    TimeDuration         `json:"allowed_reenrollment_detlta"`
	PreventiveReenrollmentDelta TimeDuration         `json:"preventive_delta"` // (expiration time - delta < time.now) at witch point an event is issued notify its time to reenroll
	CriticalDetla               TimeDuration         `json:"critical_delta"`   // (expiration time - delta < time.now) at witch point an event is issued notify critical status
	SecretType                  CryptoSecretType     `json:"type"`
	Secrets                     map[int]E            `json:"versions"` // version -> secret
	Logs                        map[time.Time]LogMsg `json:"logs"`
}

type LogMsg struct {
	Msg       string       `json:"message"`
	Criticity LogCriticity `json:"criticity"`
}

type LogCriticity string

const (
	InfoCriticity  LogCriticity = "INFO"
	ErrorCriticity LogCriticity = "ERROR"
	WarnCriticity  LogCriticity = "WARN"
)

type Criticity string

const (
	Critical Criticity = "CRITICAL"
	WARN     Criticity = "WARN"
	INFO     Criticity = "INFO"
	ERRO     Criticity = "ERROR"
)

type DeviceLog struct {
	ID        string            `json:"id"`
	Message   string            `json:"message"`
	Criticity Criticity         `json:"criticity"`
	Metadata  map[string]string `json:"metadata"`
}
