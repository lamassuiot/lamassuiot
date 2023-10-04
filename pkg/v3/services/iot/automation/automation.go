package iot

import "time"

type IotService[E any] interface {
	UpdateDigitalTwin(input DigitalTwinIdentityState) error
	GetRemediateTrackers() ([]*RemediateTracker, error)
}

type RemediateTracker struct {
	DeviceID                     string
	LastDigitalTwinIdentityState *DigitalTwinIdentityStateTracker
	Historical                   DigitalTwinIdentityStateTracker
}

type DigitalTwinIdentityStateTracker struct {
	ID           string
	Remediated   bool
	CreatedAt    time.Time
	RemediatedAt time.Time
	State        DigitalTwinIdentityState
	// RemediationActions []RemediationAction
}

type RemediationActionType string

const (
	UpdateTrustAnchorList RemediationActionType = "UPDATE_TRUST_ANCHOR_LIST"
	UpdateCertificate     RemediationActionType = "UPDATE_CERTIFICATE"
)

type DigitalTwinIdentityState struct {
	ID      string
	Actions struct {
		ReEnrol    bool
		CARotation bool
	}
	LamassuConfiguration struct {
		URL   string
		DMSID string
	}
}
