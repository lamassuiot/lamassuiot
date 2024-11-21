package errs

type APIError interface {
	// APIError returns an HTTP status code and an API-safe error message.
	APIError() (int, string)
}

type SentinelAPIError struct {
	Status int
	Msg    string
}

func (e SentinelAPIError) Error() string {
	return e.Msg
}

func (e SentinelAPIError) APIError() (int, string) {
	return e.Status, e.Msg
}

type sentinelWrappedError struct {
	error
	sentinel *SentinelAPIError
}

func (e sentinelWrappedError) Is(err error) bool {
	return e.sentinel == err
}

func (e sentinelWrappedError) APIError() (int, string) {
	return e.sentinel.APIError()
}

func WrapError(err error, sentinel *SentinelAPIError) error {
	return sentinelWrappedError{error: err, sentinel: sentinel}
}
