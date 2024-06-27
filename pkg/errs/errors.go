package errs

type HttpAPIError struct {
	Status int
	Msg    string
}

func (e HttpAPIError) Error() string {
	return e.Msg
}

func (e HttpAPIError) APIError() (int, string) {
	return e.Status, e.Msg
}
