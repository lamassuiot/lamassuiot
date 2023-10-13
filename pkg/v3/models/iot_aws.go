package models

type IotAWSAccountInfo struct {
	AccountID       string
	IotMQTTEndpoint string
}

type DMSMetadataIotPlatformAWS struct {
	JITPProvisioningTemplate struct {
		EnableTemplate            bool
		JITPName                  string   `json:"jitp_name,omitempty"`
		JITPGroupName             string   `json:"jitp_group_name,omitempty"`
		JITPInlinePolicies        []string `json:"jitp_inline_policies,omitempty"`
		JITPExternalPoliciesNames []string `json:"jitp_external_policy_names,omitempty"`
	}
}

type ShadowType string

const (
	AWSIoTShadowClasic ShadowType = "CLASSIC_SHADOW"
	AWSIoTShadowNamed  ShadowType = "NAMED_SHADOW"
)

type DMSMetadataIotAutomationAWS struct {
	DistributeCACertsInRetainedTopic bool
	ShadowType                       ShadowType
	NamedShadowName                  string
}

type PlatformConnectorAWSCAMetadata struct {
	Account       string `json:"account"`
	Region        string `json:"region"`
	ARN           string `json:"arn"`
	CertificateID string `json:"certificate_id"`
}
