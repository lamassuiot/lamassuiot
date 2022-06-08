package dto

type DmsCreationResponse struct {
	Dms     DMS    `json:"dms,omitempty"`
	PrivKey string `json:"priv_key,omitempty"`
}
type GetDmsResponse struct {
	TotalDmss int   `json:"total_dmss"`
	Dmss      []DMS `json:"dmss,omitempty"`
}
