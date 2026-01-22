package errs

import "errors"

var (
	ErrDeviceNotFound      error = errors.New("device not found")
	ErrDeviceAlreadyExists error = errors.New("device already exists")
	ErrDeviceInvalidStatus error = errors.New("device status does not allow this operation")
)
