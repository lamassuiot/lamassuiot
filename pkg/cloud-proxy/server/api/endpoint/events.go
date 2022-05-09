package endpoint

// io.lamassu.ca.create & io.lamassu.ca.import
type LamassuCaCreateEvent struct {
	CaName       string `json:"name"`
	CaCert       string `json:"cert"`
	SerialNumber string `json:"serial_number"`
}

// io.lamassu.ca.update
type LamassuCaUpdateStatusEvent struct {
	CaName string `json:"name"`
	Status string `json:"status"`
}

// io.lamassu.cert.update
type LamassuCertUpdateStatusEvent struct {
	CaName       string `json:"name"`
	Status       string `json:"status"`
	SerialNumber string `json:"serial_number"`
}
