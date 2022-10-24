package api

type CreateCASubjectPayload struct {
	CommonName       string `json:"common_name"`
	Organization     string `json:"organization"`
	OrganizationUnit string `json:"organization_unit"`
	Country          string `json:"country"`
	State            string `json:"state"`
	Locality         string `json:"locality"`
}

type CreacteCAKeyMetadataSubject struct {
	KeyType string `json:"type"`
	KeyBits int    `json:"bits"`
}

type CreateCAPayload struct {
	Subject          CreateCASubjectPayload      `json:"subject"`
	KeyMetadata      CreacteCAKeyMetadataSubject `json:"key_metadata"`
	CADuration       int                         `json:"ca_duration"`
	IssuanceDuration int                         `json:"issuance_duration"`
}

// -------------------------------------------------------------

type SignCertificateRequestPayload struct {
	CertificateRequest string `json:"certificate_request"`
	SignVerbatim       bool   `json:"sign_verbatim"`
	CommonName         string `json:"common_name,omitempty"`
}

// -------------------------------------------------------------

type RevokeCAPayload struct {
	RevocationReason string `json:"revocation_reason"`
}

// -------------------------------------------------------------

type RevokeCertificatePayload struct {
	RevocationReason string `json:"revocation_reason"`
}
