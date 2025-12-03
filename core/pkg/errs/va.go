package errs

import "errors"

var (
	ErrVARoleNotFound error = errors.New("VA role not found")
)
