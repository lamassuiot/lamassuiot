package errs

import "errors"

var (
	ErrKeyNotFound error = errors.New("key not found")
)
