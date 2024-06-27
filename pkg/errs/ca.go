package errs

var (
	ErrCryptoEngineNotFound HttpAPIError = HttpAPIError{Status: 404, Msg: "crypto engine not found"}

	ErrCANotFound HttpAPIError = HttpAPIError{Status: 404, Msg: "CA not found"}

	ErrCAAlreadyExists              HttpAPIError = HttpAPIError{Status: 409, Msg: "CA already exists"}
	ErrCAStatusTransitionNotAllowed HttpAPIError = HttpAPIError{Status: 400, Msg: "new status transition not allowed for CA"}
	ErrCAInvalidStatus              HttpAPIError = HttpAPIError{Status: 400, Msg: "invalid CA status"}

	ErrCAAlreadyRevoked       HttpAPIError = HttpAPIError{Status: 400, Msg: "CA already revoked"}
	ErrCAIncompatibleHashFunc HttpAPIError = HttpAPIError{Status: 400, Msg: "CA hash function is incompatible with the requested operation"}

	ErrCertificateNotFound                   HttpAPIError = HttpAPIError{Status: 404, Msg: "certificate not found"}
	ErrCertificateAlreadyRevoked             HttpAPIError = HttpAPIError{Status: 400, Msg: "certificate already revoked"}
	ErrCertificateStatusTransitionNotAllowed HttpAPIError = HttpAPIError{Status: 400, Msg: "new status transition not allowed for certificate"}
)
