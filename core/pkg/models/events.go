package models

import "fmt"

const ContextSourceKey = "_lms/event-source-id"
const HttpSourceHeader = "x-lms-source"

const CASource = "lrn://service/lamassuiot-ca"
const DMSManagerSource = "lrn://service/lamassuiot-ra"
const DeviceManagerSource = "lrn://service/lamassuiot-devmanager"
const VASource = "lrn://service/lamassuiot-va"
const AlertsSource = "lrn://service/lamassuiot-alerts"

func AWSIoTSource(id string) string { return fmt.Sprintf("lrn://service/lamassuiot-awsiot/%s", id) }

type UpdateModel[E any] struct {
	Previous E `json:"previous"`
	Updated  E `json:"updated"`
}

type EventType string

const (
	EventCreateCAKey         EventType = "ca.create"
	EventImportCAKey         EventType = "ca.import"
	EventUpdateCAStatusKey   EventType = "ca.update.status"
	EventUpdateCAMetadataKey EventType = "ca.update.metadata"
	EventSignCertificateKey  EventType = "ca.sign.certificate"
	EventSignatureSignKey    EventType = "ca.sign.signature"
	EventDeleteCAKey         EventType = "ca.delete"

	EventCreateCertificateKey         EventType = "certificate.create"
	EventImportCertificateKey         EventType = "certificate.import"
	EventUpdateCertificateStatusKey   EventType = "certificate.update.status"
	EventUpdateCertificateMetadataKey EventType = "certificate.update.metadata"

	EventCreateDMSKey          EventType = "dms.create"
	EventUpdateDMSMetadataKey  EventType = "dms.update.metadata"
	EventEnrollKey             EventType = "dms.enroll"
	EventReEnrollKey           EventType = "dms.reenroll"
	EventBindDeviceIdentityKey EventType = "dms.bind-device-id"

	EventCreateDeviceKey         EventType = "device.create"
	EventUpdateDeviceIDSlotKey   EventType = "device.update.identity"
	EventUpdateDeviceStatusKey   EventType = "device.update.status"
	EventUpdateDeviceMetadataKey EventType = "device.update.metadata"
)
