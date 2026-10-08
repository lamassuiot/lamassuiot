package errs

import "errors"

var (
	ErrVARoleNotFound      error = errors.New("VA role not found")
	ErrVARoleAlreadyExists error = errors.New("VA role already exists")
)
