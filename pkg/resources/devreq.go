package resources

type CreateDeviceBody struct {
	ID        string            `json:"id"`
	Alias     string            `json:"alias"`
	Tags      []string          `json:"tags"`
	Metadata  map[string]string `json:"metadata"`
	DMSID     string            `json:"dms_id"`
	Icon      string            `json:"icon"`
	IconColor string            `json:"icon_color"`
}
