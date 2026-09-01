package cryptoenginesv2

import "context"

// Wrap. alg selects the wrapping algorithm (e.g. RSAES_OAEP_SHA_256) and must
// be compatible with the key's KeySpec.
type KeyWrapper interface {
	KeyHandle
	WrapKey(ctx context.Context, keyMaterial []byte, alg AlgorithmID, opts WrapOpts) (wrapped []byte, err error)
	UnwrapKey(ctx context.Context, wrapped []byte, alg AlgorithmID, opts WrapOpts) (keyMaterial []byte, err error)
}
