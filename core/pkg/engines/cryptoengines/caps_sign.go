package cryptoengines

import "crypto"

// Signer is the capability of signing keys. It embeds crypto.Signer, so code built on the standard library,
// such as x509, keeps working with it.
type Signer interface {
	KeyHandle
	crypto.Signer
}
