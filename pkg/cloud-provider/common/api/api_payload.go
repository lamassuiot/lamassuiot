package api

import caApi "github.com/lamassuiot/lamassuiot/pkg/ca/common/api"

type UpdateDeviceCertificateStatusPayload struct {
	CAName       string `json:"ca_name"`
	SerialNumber string `json:"serial_number"`
	Status       string `json:"status"`
}

type RegisterCAPayload struct {
	caApi.CACertificateSerialized
}
