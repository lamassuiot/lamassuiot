package models

type Subject struct {
	CommonName       string `json:"common_name"`
	Organization     string `json:"organization"`
	OrganizationUnit string `json:"organization_unit" `
	Country          string `json:"country"`
	State            string `json:"state"`
	Locality         string `json:"locality"`
}
