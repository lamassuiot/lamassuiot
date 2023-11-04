package models

import (
	"fmt"
	"time"
)

type DigitalTwinIdentityState map[RemediationActionType]*DigitalTwinActionTracker
type RemediateTracker struct {
	ActiveDigitalTwinIdentityState DigitalTwinIdentityState
	Historical                     []*DigitalTwinActionTracker
}

type DigitalTwinActionTracker struct {
	TriggeredBy  string                            `json:"triggered_by"`
	Remediated   bool                              `json:"remediated"`
	CreatedAt    time.Time                         `json:"created_at"`
	RemediatedAt time.Time                         `json:"remediated_at"`
	State        DigitalTwinRemediationActionState `json:"remediation"`
}

type RemediationActionType string

const (
	RemediationActionUpdateTrustAnchorList RemediationActionType = "UPDATE_TRUST_ANCHOR_LIST"
	RemediationActionUpdateCertificate     RemediationActionType = "UPDATE_CERTIFICATE"
)

type DigitalTwinRemediationActionState struct {
	RemediationType RemediationActionType `json:"action"`
	LamassuInstance LamassuConfiguration  `json:"lamassu_instance"`
}

type LamassuConfiguration struct {
	URL   string `json:"url"`
	DMSID string `json:"dms_id"`
}

func AWSIoTMetadataKey(connectorID string) string {
	return fmt.Sprintf("lamassu.io/iot/%s", connectorID)
}

type IoTAWSCAMetadata struct {
	Register            bool   `json:"register"`
	Account             string `json:"account"`
	Region              string `json:"region"`
	ARN                 string `json:"arn"`
	CertificateID       string `json:"certificate_id"`
	IotCoreMQTTEndpoint string `json:"mqtt_endpoint"`
}

type IotAWSDMSMetadata struct {
	JITPProvisioningTemplate struct {
		ProvisioningRoleArn string       `json:"provisioning_role_arn"`
		EnableTemplate      bool         `json:"enable_template"`
		JITPGroupNames      []string     `json:"jitp_group_names,omitempty"`
		JITPPolicies        []JITPPolicy `json:"jitp_policies,omitempty"`
	} `json:"jitp_config,omitempty"`
	ShadowConfig struct {
		Enable     bool   `json:"enable"`
		ShadowName string `json:"shadow_name,omitempty"`
	} `json:"shadow_config,omitempty"`
}

type JITPPolicy struct {
	PolicyName     string `json:"policy_name"`
	PolicyDocument string `json:"policy_document"`
}
