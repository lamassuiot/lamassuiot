package errs

var (
	ErrInvalidInput HttpAPIError = HttpAPIError{Status: 400, Msg: "invalid input"}
)
