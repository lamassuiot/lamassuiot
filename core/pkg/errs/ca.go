package errs

import "errors"

var (
	ErrCryptoEngineNotFound error = errors.New("crypto engine not found")

	ErrCANotFound             error = errors.New("CA not found")
	ErrCAAlreadyExists        error = errors.New("CA already exists")
	ErrCAStatus               error = errors.New("CA Status inconsistent")
	ErrCAAlreadyRevoked       error = errors.New("CA already revoked")
	ErrCAOnHold               error = errors.New("CA is on hold")
	ErrCAExpired              error = errors.New("CA is expired")
	ErrCAIncompatibleHashFunc error = errors.New("incompatible hash function")
	ErrCAIncompatibleValidity error = errors.New("incompatible expiration time ref")
	ErrCAIssuanceExpiration   error = errors.New("issuance expiration greater than CA expiration")
	ErrCAType                 error = errors.New("CA type inconsistent")
	ErrCAValidCertAndPrivKey  error = errors.New("CA and the provided key don't match")

	ErrValidateBadRequest error = errors.New("struct validation error")

	ErrCertificateNotFound                   error = errors.New("certificate not found")
	ErrCertificateAlreadyRevoked             error = errors.New("certificate already revoked")
	ErrCertificateStatusTransitionNotAllowed error = errors.New("new status transition not allowed for certificate")
	ErrCertificateIssuerCAExists             error = errors.New("cannot delete certificate: issuer CA still exists")

	ErrCascadeDeleteNotAllowed error = errors.New("cascade delete operations are not allowed by configuration")

	ErrIssuanceProfileNotFound error = errors.New("issuance profile not found")

	//KMS
	ErrKeyNotFound error = errors.New("key not found")
	// A key is identified by (key_id, engine_id), so a keyID held by more than one engine
	// does not address a single key.
	ErrKeyEngineRequired error = errors.New("keyID is held by several engines: identify the key by its pkcs11 URI or one of its aliases")
	// A keyID wins over an alias when resolving an identifier, so such an alias would never
	// resolve to the key it was set on.
	ErrKeyAliasCollidesWithKeyID error = errors.New("alias collides with an existing keyID")

	// CreateCertificate
	ErrInvalidKeySpec error = errors.New("invalid key spec: exactly one of (Type+Bits) or KeyIdentifier must be provided")
)
