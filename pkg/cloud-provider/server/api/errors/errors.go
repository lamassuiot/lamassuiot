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

type DuplicateResourceError struct {
	ResourceType string
	ResourceId   string
}

func (e *DuplicateResourceError) Error() string {
	return fmt.Sprintf("resource already exists. resource_type=%s resource_id=%s", e.ResourceType, e.ResourceId)
}

type ResourceNotFoundError struct {
	ResourceType string
	ResourceId   string
}

func (e *ResourceNotFoundError) Error() string {
	return fmt.Sprintf("resource not found. resource_type=%s resource_id=%s", e.ResourceType, e.ResourceId)
}

type GenericError struct {
	Message    string
	StatusCode int
}

func (e *GenericError) Error() string {
	return fmt.Sprintf("%s", e.Message)
}
