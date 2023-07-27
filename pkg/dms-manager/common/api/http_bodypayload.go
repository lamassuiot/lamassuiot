package api

type CreateDMSSubjectPayload struct {
	CommonName       string `json:"common_name"`
	Organization     string `json:"organization"`
	OrganizationUnit string `json:"organization_unit"`
	Country          string `json:"country"`
	State            string `json:"state"`
	Locality         string `json:"locality"`
}

type CreateDMSKeyMetadataPayload struct {
	KeyType string `json:"type"`
	KeyBits int    `json:"bits"`
}

type CreateDMSPayload struct {
	Name                 string                         `json:"name"`
	CloudDMS             bool                           `json:"cloud_dms"`
	IdentityProfile      IdentityProfileSerialized      `json:"identity_profile"`
	RemoteAccessIdentity RemoteAccessIdentitySerialized `json:"remote_access_identity"`
	Aws                  AwsSpecificationSerialized     `json:"aws"`
}

type UpdateMSPayload struct {
	DeviceManufacturingServiceSerialized
}

// -------------------------------------------------------------

type UpdateDMSStatusPayload struct {
	Status string `json:"status"`
}

// -------------------------------------------------------------

type UpdateDMSAuthorizedCAsPayload struct {
	AuthorizedCAs []string `json:"authorized_cas"`
}

// -------------------------------------------------------------

type RevokeCertificatePayload struct {
	RevocationReason string `json:"revocation_reason"`
}
