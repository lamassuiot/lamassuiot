package models

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

	EventCreateDMSKey         EventType = "dms.create"
	EventUpdateDMSMetadataKey EventType = "dms.update.metadata"
)
