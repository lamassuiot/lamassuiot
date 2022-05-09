package dto

type SignResponse struct {
	Crt   string `json:"crt"`
	CaCrt string `json:"cacrt"`
}
type IssuedCertsResponse struct {
	TotalCerts int    `json:"total_certs"`
	Certs      []Cert `json:"certs,omitempty"`
}
