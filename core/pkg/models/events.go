package models

const HttpSourceHeader = "x-lms-source"
const HttpRequestIDHeader = "x-request-id"

const KMSSource = "service/kms"
const CASource = "service/ca"
const DMSManagerSource = "service/ra"
const DeviceManagerSource = "service/devmanager"
const VASource = "service/va"
const AlertsSource = "service/alerts"

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
	EventReissueCAKey           EventType = "ca.reissue"
	EventSignCertificateKey     EventType = "ca.sign.certificate"
	EventSignatureSignKey       EventType = "ca.sign.signature"
	EventDeleteCAKey            EventType = "ca.delete"

	EventCreateKMSKey           EventType = "kms.create"
	EventImportKMSKey           EventType = "kms.import"
	EventUpdateKMSKeyMetadata   EventType = "kms.metadata.update"
	EventUpdateKMSKeyAliases    EventType = "kms.aliases.update"
	EventUpdateKMSKeyName       EventType = "kms.name.update"
	EventUpdateKMSKeyTags       EventType = "kms.tags.update"
	EventDeleteKMSKey           EventType = "kms.delete"
	EventSignMessageKMSKey      EventType = "kms.sign"
	EventVerifySignatureKMSKey  EventType = "kms.verify"
	EventRegisterExistingKMSKey EventType = "kms.register.existing"

	EventCreateIssuanceProfileKey EventType = "profile.issuance.create"
	EventUpdateIssuanceProfileKey EventType = "profile.issuance.update"
	EventDeleteIssuanceProfileKey EventType = "profile.issuance.delete"

	EventCreateCertificateKey         EventType = "certificate.create"
	EventImportCertificateKey         EventType = "certificate.import"
	EventUpdateCertificateStatusKey   EventType = "certificate.status.update"
	EventUpdateCertificateMetadataKey EventType = "certificate.metadata.update"
	EventDeleteCertificateKey         EventType = "certificate.delete"

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

	EventCreateDeviceGroupKey EventType = "device-group.create"
	EventUpdateDeviceGroupKey EventType = "device-group.update"
	EventDeleteDeviceGroupKey EventType = "device-group.delete"

	EventUpdateVARole EventType = "va.role.update"
	EventInitCRLRole  EventType = "va.role.crl.init"
	EventCreateCRL    EventType = "va.role.crl.create"

	EventAnyKey EventType = "any"
)
