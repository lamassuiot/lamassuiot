package client

import (
	"fmt"
	"net/http"
)

// estError is an internal error structure implementing est.Error.
type estError struct {
	status     int
	desc       string
	retryAfter int
}

// Internal error values.
var (
	errInvalidBase64 = &estError{
		status: http.StatusBadRequest,
		desc:   "invalid base64 encoding",
	}
	errInvalidPKCS7 = &estError{
		status: http.StatusBadRequest,
		desc:   "malformed PKCS7 structure",
	}
)

// StatusCode returns the HTTP status code.
func (e estError) StatusCode() int {
	return e.status
}

// Error returns a human-readable description of the error.
func (e estError) Error() string {
	if e.desc == "" {
		return http.StatusText(e.status)
	}

	return e.desc
}

// RetryAfter returns the value in seconds after which the client should
// retry the request.
func (e estError) RetryAfter() int {
	return e.retryAfter
}

// Write writes the error to the supplied writer.
func (e estError) Write(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(e.status)
	w.Write([]byte(fmt.Sprintf("%d %s\n", e.status, e.desc)))
}
