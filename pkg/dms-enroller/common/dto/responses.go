package dto

type DmsCreationResponse struct {
	Dms     DMS    `json:"dms,omitempty"`
	PrivKey string `json:"priv_key,omitempty"`
}
