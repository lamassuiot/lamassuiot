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
	Subject     CreateDMSSubjectPayload     `json:"subject"`
	KeyMetadata CreateDMSKeyMetadataPayload `json:"key_metadata"`
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

// -------------------------------------------------------------

type CreateDMSWithCertificateRequestPayload struct {
	CertificateRequest string `json:"certificate_request"`
}
