package dto

type DMS struct {
	Id                    string                        `json:"id"`
	Name                  string                        `json:"name"`
	SerialNumber          string                        `json:"serial_number,omitempty"`
	KeyMetadata           PrivateKeyMetadataWithStregth `json:"key_metadata"`
	Status                string                        `json:"status"`
	CsrBase64             string                        `json:"csr,omitempty"`
	CerificateBase64      string                        `json:"crt,omitempty"`
	Subject               Subject                       `json:"subject,omitempty"`
	AuthorizedCAs         []string                      `json:"authorized_cas,omitempty"`
	CreationTimestamp     string                        `json:"creation_timestamp,omitempty"`
	ModificationTimestamp string                        `json:"modification_timestamp,omitempty"`
	EnrolledDevices       int                           `json:"enrolled_devices"`
}
type PrivateKeyMetadataWithStregth struct {
	KeyType     string `json:"type,omitempty"`
	KeyBits     int    `json:"bits,omitempty"`
	KeyStrength string `json:"strength,omitempty"`
}
type PrivateKeyMetadata struct {
	KeyType string `json:"type" validate:"oneof='RSA' 'EC'"`
	KeyBits int    `json:"bits"`
}
type Subject struct {
	CN string `json:"common_name" validate:"required"`
	O  string `json:"organization,omitempty"`
	OU string `json:"organization_unit,omitempty"`
	C  string `json:"country,omitempty"`
	ST string `json:"state,omitempty"`
	L  string `json:"locality,omitempty"`
}
