package models

const HttpSourceHeader = "x-lms-source"
const HttpRequestIDHeader = "x-request-id"

const CASource = "lrn://service/lamassuiot-ca"
const DMSManagerSource = "lrn://service/lamassuiot-ra"
const DeviceManagerSource = "lrn://service/lamassuiot-devmanager"
const VASource = "lrn://service/lamassuiot-va"
const AlertsSource = "lrn://service/lamassuiot-alerts"

type UpdateModel[E any] struct {
	Previous E `json:"previous"`
	Updated  E `json:"updated"`
}

type EventType string

const (
	EventCreateCAKey            EventType = "ca.create"
	EventRequestCAKey           EventType = "ca.request"
	EventImportCAKey            EventType = "ca.import"
	EventImportCACertificateKey EventType = "ca.certificate.import"
	EventUpdateCAProfileKey     EventType = "ca.profile.update"
	EventUpdateCAStatusKey      EventType = "ca.status.update"
	EventUpdateCAMetadataKey    EventType = "ca.metadata.update"
	EventSignCertificateKey     EventType = "ca.sign.certificate"
	EventSignatureSignKey       EventType = "ca.sign.signature"
	EventDeleteCAKey            EventType = "ca.delete"

	EventCreateCertificateKey         EventType = "certificate.create"
	EventImportCertificateKey         EventType = "certificate.import"
	EventUpdateCertificateStatusKey   EventType = "certificate.status.update"
	EventUpdateCertificateMetadataKey EventType = "certificate.metadata.update"

	EventCreateDMSKey          EventType = "dms.create"
	EventUpdateDMSKey          EventType = "dms.update"
	EventUpdateDMSMetadataKey  EventType = "dms.metadata.update"
	EventDeleteDMSKey          EventType = "dms.delete"
	EventEnrollKey             EventType = "dms.enroll"
	EventReEnrollKey           EventType = "dms.reenroll"
	EventBindDeviceIdentityKey EventType = "dms.bind-device-id"

	EventCreateDeviceKey         EventType = "device.create"
	EventUpdateDeviceIDSlotKey   EventType = "device.identity.update"
	EventUpdateDeviceStatusKey   EventType = "device.status.update"
	EventUpdateDeviceMetadataKey EventType = "device.metadata.update"
	EventDeleteDeviceKey         EventType = "device.delete"

	EventUpdateVARole EventType = "va.role.update"
	EventCreateCRL    EventType = "va.crl.create"

	EventAnyKey EventType = "any"
)
