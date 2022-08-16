package common

type AzureCredentials struct {
	AzureSecret         string
	AzureTenantId       string
	AzureClientId       string
	AzureSasTokenKey    string
	AzureHubSasTokenKey string
}

type CreateOrUpdateCertificate struct {
	Certificate string
}

type CreateOrUpdateEnrollmentGroup struct {
	Attestation        Attestation `json:"attestation" required:"true"`
	EnrollmentGroupId  string      `json:"enrollmentGroupId" required:"true"`
	ProvisioningStatus string      `json:"provisioningStatus"`
}

type CaReferences struct {
	Primary string `json:"primary" required:"true"`
}

type X509 struct {
	CaReferences CaReferences `json:"caReferences"`
}

type Attestation struct {
	AttType string `json:"type" required:"true"`
	X509    X509   `json:"x509"`
}

type IndividualAttestation struct {
	AttType string `json:"type" required:"true"`
}
type CreateOrUpdateIndividualEnrollment struct {
	Attestation        IndividualAttestation `json:"attestation" required:"true"`
	RegistrationId     string                `json:"registrationId" required:"true"`
	ProvisioningStatus string                `json:"provisioningStatus"`
	DeviceId           string                `json:"deviceId"`
}

type DeviceInfo struct {
	DeviceId                   string `json:"deviceId"`
	GenerationId               string `json:"generationId"`
	Etag                       string `json:"etag"`
	ConnectionState            string `json:"connectionState"`
	Status                     string `json:"status"`
	StatusReason               string `json:"statusReason"`
	ConnectionStateUpdatedTime string `json:"connectionStateUpdatedTime"`
	StatusUpdatedTime          string `json:"statusUpdatedTime"`
	LastActivityTime           string `json:"lastActivityTime"`
	CloudToDeviceMessageCount  int    `json:"cloudToDeviceMessageCount"`
}

type RegistrationRecord struct {
	RegistrationID string `json:"registrationId"`
	DeviceID       string `json:"deviceId"`
	AssignedHub    string `json:"assignedHub"`
}

type AzureConfig struct {
	SubscriptionId string    `json:"subscription_id"`
	TenantId       string    `json:"tenant_id"`
	ResourceGroup  string    `json:"resource_group"`
	DpsEndpoint    string    `json:"dps_endpoint"`
	RegisteredCas  []AzureCa `json:"registered_cas"`
}

type AzureCa struct {
	CaName string `json:"ca_name"`
}
