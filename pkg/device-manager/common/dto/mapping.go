package dto

import (
	"crypto/x509"
)

type Stats struct {
	PendingEnrollment int `json:"pending_enrollment"`
	Provisioned       int `json:"provisioned"`
	Decomissioned     int `json:"decommissioned"`
	AboutToExpire     int `json:"provisioned_devices"`
	Expired           int `json:"expired"`
	Revoked           int `json:"revoked"`
}

type Device struct {
	Id                    string                        `json:"id"`
	Alias                 string                        `json:"alias"`
	Description           string                        `json:"description"`
	Tags                  []string                      `json:"tags"`
	IconName              string                        `json:"icon_name"`
	IconColor             string                        `json:"icon_color"`
	Status                string                        `json:"status,omitempty"`
	DmsId                 string                        `json:"dms_id"`
	KeyMetadata           PrivateKeyMetadataWithStregth `json:"key_metadata,omitempty"`
	Subject               Subject                       `json:"subject,omitempty"`
	CreationTimestamp     string                        `json:"creation_timestamp,omitempty"`
	ModificationTimestamp string                        `json:"modification_timestamp,omitempty"`
	CurrentCertificate    CurrentCertificate            `json:"current_certificate,omitempty"`
}

type CurrentCertificate struct {
	SerialNumber string `json:"serial_number,omitempty"`
	Valid_to     string `json:"valid_to,omitempty"`
	Cert         string `json:"crt,omitempty"`
}

type PrivateKeyMetadataWithStregth struct {
	KeyType     string `json:"type,omitempty"`
	KeyBits     int    `json:"bits,omitempty"`
	KeyStrength string `json:"strength,omitempty"`
}
type Subject struct {
	CommonName       string `json:"common_name,omitempty"`
	Organization     string `json:"organization,omitempty"`
	OrganizationUnit string `json:"organization_unit,omitempty"`
	Country          string `json:"country,omitempty"`
	State            string `json:"state,omitempty"`
	Locality         string `json:"locality,omitempty"`
}

type DeviceLog struct {
	Id         string `json:"id"`
	DeviceId   string `json:"device_id"`
	LogType    string `json:"log_type"`
	LogMessage string `json:"log_message"`
	Timestamp  string `json:"timestamp"`
}

type DMSCertHistory struct {
	DmsId       string `json:"dms_id"`
	IssuedCerts int    `json:"issued_certs"`
}

type DMSLastIssued struct {
	DmsId             string `json:"dms_id"`
	CreationTimestamp string `json:"creation_timestamp"`
	SerialNumber      string `json:"serial_number"`
}

type DeviceCertHistory struct {
	DeviceId            string `json:"device_id"`
	SerialNumber        string `json:"serial_number"`
	IsuuerName          string `json:"issuer_name"`
	Status              string `json:"status"`
	CreationTimestamp   string `json:"creation_timestamp"`
	RevocationTimestamp string `json:"revocation_timestamp"`
}

type DeviceCert struct {
	DeviceId     string  `json:"device_id"`
	SerialNumber string  `json:"serial_number"`
	CAName       string  `json:"issuer_name"`
	Status       string  `json:"status"`
	CRT          string  `json:"crt"`
	Subject      Subject `json:"subject"`
	ValidFrom    string  `json:"valid_from"`
	ValidTo      string  `json:"valid_to"`
}

type Enroll struct {
	Cert   *x509.Certificate `json:"crt"`
	CaCert *x509.Certificate `json:"cacrt"`
}

type ServerKeyGen struct {
	Cert   *x509.Certificate `json:"crt"`
	CaCert *x509.Certificate `json:"cacrt"`
	Key    []byte            `json:"key"`
}
