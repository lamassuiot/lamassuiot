package errs

import "errors"

var (
	ErrInvalidInput error = errors.New("invalid input")
)
