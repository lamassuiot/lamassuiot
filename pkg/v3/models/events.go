package models

type EventType string

const (
	EventCreateCA                  EventType = "ca.create"
	EventImportCA                  EventType = "ca.import"
	EventUpdateCAStatus            EventType = "ca.update.status"
	EventUpdateCAMetadata          EventType = "ca.update.metadata"
	EventDeleteCA                  EventType = "ca.delete"
	EventSignCertificate           EventType = "ca.certificate.sign"
	EventSignatureSign             EventType = "ca.signature.sign"
	EventCreateCertificate         EventType = "ca.certificate.create"
	EventImportCertificate         EventType = "ca.certificate.import"
	EventUpdateCertificateStatus   EventType = "ca.certificate.status"
	EventUpdateCertificateMetadata EventType = "ca.certificate.metadata"
)
