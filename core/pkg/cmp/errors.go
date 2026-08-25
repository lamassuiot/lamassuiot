package cmp

import (
	"errors"
	"fmt"
)

// ProtocolError associates an operation failure with an optional CMP
// PKIFailureInfo value suitable for a protocol response.
type ProtocolError struct {
	Operation string
	Failure   *FailureInfo
	Err       error
}

func (e *ProtocolError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Operation == "" {
		return e.Err.Error()
	}
	return fmt.Sprintf("%s: %v", e.Operation, e.Err)
}

func (e *ProtocolError) Unwrap() error { return e.Err }

// FailureInfoFromError extracts a typed PKIFailureInfo value from err.
func FailureInfoFromError(err error) (FailureInfo, bool) {
	var protocolError *ProtocolError
	if errors.As(err, &protocolError) && protocolError.Failure != nil {
		return *protocolError.Failure, true
	}
	if bit, ok := ProtectionAlgorithmFailureInfo(err); ok {
		return FailureInfo(bit), true
	}
	return 0, false
}

func protocolError(operation string, failure FailureInfo, err error) error {
	return &ProtocolError{Operation: operation, Failure: &failure, Err: err}
}
