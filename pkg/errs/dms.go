package errs

var (
	ErrDMSNotFound      = NewAPIError(errorBuilder{Status: 404, Msg: "DMS not found"})
	ErrDMSAlreadyExists = NewAPIError(errorBuilder{Status: 409, Msg: "DMS already exists"})

	ErrDMSOnlyEST              = NewAPIError(errorBuilder{Status: 400, Msg: "only EST is supported"})
	ErrDMSInvalidAuthMode      = NewAPIError(errorBuilder{Status: 400, Msg: "invalid auth mode"})
	ErrDMSAuthModeNotSupported = NewAPIError(errorBuilder{Status: 400, Msg: "auth mode not supported"})
	ErrDMSEnrollInvalidCert    = NewAPIError(errorBuilder{Status: 400, Msg: "invalid cert"})
	ErrDMSRevokedCert          = NewAPIError(errorBuilder{Status: 400, Msg: "revoked certificate"})
)
