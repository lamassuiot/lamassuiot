package errs

import "errors"

var (
	ErrCryptoEngineNotFound error = errors.New("crypto engine not found")

	ErrCANotFound                      error = errors.New("CA not found")
	ErrCAAlreadyExists                 error = errors.New("CA already exists")
	ErrCAStatusTransitionNotAllowed    error = errors.New("status transition not allowed for CA")
	ErrCAStatus                        error = errors.New("CA Status inconsistent")
	ErrCAAlreadyRevoked                error = errors.New("CA already revoked")
	ErrCAIncompatibleHashFunc          error = errors.New("incompatible hash function")
	ErrCAIncompatibleExpirationTimeRef error = errors.New("incompatible expiration time ref")
	ErrCAIssuanceExpiration            error = errors.New("issuance expiration greater than CA expiration")
	ErrCAType                          error = errors.New("CA type inconsistent")
	ErrCAValidCertAndPrivKey           error = errors.New("CA and the provided key dont match")

	ErrValidateBadRequest error = errors.New("Struct Validation error")

	ErrCertificateNotFound                   error = errors.New("certificate not found")
	ErrCertificateAlreadyRevoked             error = errors.New("cerificate already revoked")
	ErrCertificateStatusTransitionNotAllowed error = errors.New("new status transition not allowed for certificate")
)
