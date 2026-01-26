package errs

import "errors"

var (
	ErrDeviceNotFound      error = errors.New("device not found")
	ErrDeviceAlreadyExists error = errors.New("device already exists")
	ErrDeviceInvalidStatus error = errors.New("device status does not allow this operation")

	// Device Group errors
	ErrDeviceGroupNotFound          error = errors.New("device group not found")
	ErrDeviceGroupAlreadyExists     error = errors.New("device group already exists")
	ErrDeviceGroupCircularReference error = errors.New("circular parent reference detected")
)
