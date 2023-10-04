package iot

type IotPlatformService[E any] interface {
	UpdateDigitalTwin(input DigitalTwinIdentity) error
}

type DigitalTwinIdentity struct {
	Actions struct {
		ReEnrol    bool
		CARotation bool
	}
	LamassuConfiguration struct {
		URL   string
		DMSID string
	}
}
