package errors

import (
	"fmt"
)

type ValidationError struct {
	Msg string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error: %s", e.Msg)
}

type GenericError struct {
	Message    string
	StatusCode int
}

func (e *GenericError) Error() string {
	return fmt.Sprintf("%s", e.Message)
}

type UnAuthorized struct {
	ResourceType string
	ResourceId   string
}

func (e *UnAuthorized) Error() string {
	return fmt.Sprintf("Unauthorized CA Name. resource_type=%s resource_id=%s", e.ResourceType, e.ResourceId)
}
