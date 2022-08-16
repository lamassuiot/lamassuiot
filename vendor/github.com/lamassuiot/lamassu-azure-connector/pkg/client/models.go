package client

type RevokeCaBody struct {
	CaName string `json:"ca_name"`
}

type RevokeCertificateBody struct {
	DeviceId string `json:"device_id"`
	HubName  string `json:"hub_name"`
}

type UpdateCaCertificateBody struct {
	CaName string `json:"ca_name"`
}

type UpdateCertificateBody struct {
	DeviceId string `json:"device_id"`
}

type GetDeviceConfigurationBody struct {
	DeviceId string `json:"device_id"`
	HubName  string `json:"hub_name"`
}
type azureCreateDpsCA struct {
	CaName       string `json:"ca_name"`
	Certificate  string `json:"certificate"`
	SerialNumber string `json:"serial_number"`
}
