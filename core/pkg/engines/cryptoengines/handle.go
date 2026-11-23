package cryptoengines

// KeyHandle answers "which key": one key loaded for one request. It does no cryptography itself; what the key
// can do is given by the capability interfaces it implements (Signer).
type KeyHandle interface {
	Ref() KeyRef
}
