package cryptoenginesv2

import (
	"context"
	"crypto"
)

// Signing
//
// The alg argument selects the per-operation signing algorithm (scheme + hash,
// e.g. RSASSA_PSS_SHA_256); it must be compatible with the key's KeySpec. The
// embedded crypto.Signer.Sign method is retained for stdlib interop and infers
// the algorithm from opts (PSS via *rsa.PSSOptions, hash via HashFunc()).
type Signer interface {
	KeyHandle
	crypto.Signer
	SignContext(ctx context.Context, data []byte, alg AlgorithmID, opts crypto.SignerOpts) ([]byte, error)
}

type MessageSigner interface {
	Signer
	crypto.MessageSigner
	SignMessageContext(ctx context.Context, msg []byte, alg AlgorithmID, opts crypto.SignerOpts) ([]byte, error)
}

type Verifier interface {
	KeyHandle
	Verify(ctx context.Context, data, signature []byte, alg AlgorithmID, opts crypto.SignerOpts) error
}
