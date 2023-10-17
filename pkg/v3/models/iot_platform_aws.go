package models

import "fmt"

type IotAWSAccountInfo struct {
	AccountID       string
	IotMQTTEndpoint string
}

type DMSMetadataIotPlatformAWS struct {
	JITPProvisioningTemplate struct {
		EnableTemplate bool         `json:"enable_template,omitempty"`
		JITPGroupNames []string     `json:"jitp_group_names,omitempty"`
		JITPPolicies   []JITPPolicy `json:"jitp_policies,omitempty"`
	}
	JobsEnabled bool `json:"jobs_enabled"`
}
type JITPPolicy struct {
	Name   string `json:"name"`
	Policy string `json:"policy"`
}

func DMSMetadataIotPlatformKey(connectorID string) string {
	return fmt.Sprintf("lamassu.io/dms/iot-platform/%s", connectorID)
}

type PlatformConnectorAWSCAMetadata struct {
	Account       string `json:"account"`
	Region        string `json:"region"`
	ARN           string `json:"arn"`
	CertificateID string `json:"certificate_id"`
}
