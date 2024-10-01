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

type IoTAWSCAMetadataRegistrationStatus string

const (
	IoTAWSCAMetadataRegistrationRequested IoTAWSCAMetadataRegistrationStatus = "REQUESTED"
	IoTAWSCAMetadataRegistrationFailed    IoTAWSCAMetadataRegistrationStatus = "FAILED"
	IoTAWSCAMetadataRegistrationSucceeded IoTAWSCAMetadataRegistrationStatus = "SUCCEEDED"
)

type IoTAWSCAMetadataRegistration struct {
	RegistrationRequestTime time.Time                          `json:"registration_request_time"`
	RegistrationTime        time.Time                          `json:"registration_time"`
	Status                  IoTAWSCAMetadataRegistrationStatus `json:"status"`
	Error                   string                             `json:"error"`
	PrimaryAccount          bool                               `json:"primary_account"`
}

type IoTAWSCAMetadata struct {
	Registration        IoTAWSCAMetadataRegistration `json:"registration"`
	Account             string                       `json:"account"`
	Region              string                       `json:"region"`
	ARN                 string                       `json:"arn"`
	CertificateID       string                       `json:"certificate_id"`
	IotCoreMQTTEndpoint string                       `json:"mqtt_endpoint"`
}
type IoTAWSCertificateMetadata struct {
	ARN string `json:"arn"`
}

type AWSIoTRegistrationMode string

const (
	NoneAWSIoTRegistrationMode      = "none"
	JitpAWSIoTRegistrationMode      = "jitp"
	AutomaticAWSIoTRegistrationMode = "auto"
)

type IotAWSDMSMetadata struct {
	RegistrationMode         AWSIoTRegistrationMode `json:"registration_mode"`
	GroupNames               []string               `json:"groups,omitempty"`
	Policies                 []AWSIoTPolicy         `json:"policies,omitempty"`
	JITPProvisioningTemplate struct {
		ARN                 string `json:"arn,omitempty"`
		AWSCACertificateId  string `json:"aws_ca_id,omitempty"`
		ProvisioningRoleArn string `json:"provisioning_role_arn"`
		EnableTemplate      bool   `json:"enable_template"`
	} `json:"jitp_config,omitempty"`
	ShadowConfig struct {
		Enable     bool   `json:"enable"`
		ShadowName string `json:"shadow_name,omitempty"`
	} `json:"shadow_config,omitempty"`
}

type AWSIoTPolicy struct {
	PolicyName     string `json:"policy_name"`
	PolicyDocument string `json:"policy_document"`
}

type DeviceAWSMetadata struct {
	Registered bool                    `json:"thing_registered"`
	Actions    []RemediationActionType `json:"actions"`
}
