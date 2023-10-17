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

func DeviceMetadataIotAutomationKey(connectorID string) string {
	return fmt.Sprintf("lamassu.io/iot-automation/%s", connectorID)
}

func DMSMetadataIotAutomationKey(connectorID string) string {
	return fmt.Sprintf("lamassu.io/iot-automation/%s", connectorID)
}

func CAMetadataIotAutomationKey(connectorID string) string {
	return fmt.Sprintf("lamassu.io/iot-automation/%s", connectorID)
}
