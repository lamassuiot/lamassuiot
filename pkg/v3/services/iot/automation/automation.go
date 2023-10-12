package iot

import "time"

type IotDeviceLifeCycleAutomationService interface {
	UpdateDigitalTwin(input UpdateDigitalTwinInput) error
	GetRemediateTrackers() ([]*RemediateTracker, error)
}
type UpdateDigitalTwinInput struct {
	DeviceID string
	Action   RemediationActionType
}

type RemediateTracker struct {
	DeviceID                     string
	LastDigitalTwinIdentityState *DigitalTwinIdentityStateTracker
	Historical                   DigitalTwinIdentityStateTracker
}

type DigitalTwinIdentityStateTracker struct {
	ID              string
	Remediated      bool
	CreatedAt       time.Time
	RemediatedAt    time.Time
	State           DigitalTwinIdentityState
	RemediationType RemediationActionType
}

type RemediationActionType string

const (
	UpdateTrustAnchorList RemediationActionType = "UPDATE_TRUST_ANCHOR_LIST"
	UpdateCertificate     RemediationActionType = "UPDATE_CERTIFICATE"
)

type DigitalTwinIdentityState struct {
	LamassuConfiguration struct {
		URL   string
		DMSID string
	}
}
