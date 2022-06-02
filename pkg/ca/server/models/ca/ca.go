package ca

type IssuedCerts struct {
	CaName       string `json:"ca_name"`
	SerialNumber string `json:"serial_number"`
}
type Cas struct {
	CaName string `json:"ca_name"`
	CaType string `json:"ca_type"`
}
