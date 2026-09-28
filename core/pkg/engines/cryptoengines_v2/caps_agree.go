package cryptoenginesv2

import (
	"context"
	"crypto"
)

// Key agreement. alg selects the agreement algorithm (ECDH) and must be
// compatible with the key's KeySpec.
type KeyAgreementer interface {
	KeyHandle
	Agree(ctx context.Context, peerPublic crypto.PublicKey, alg AlgorithmID) (sharedSecret []byte, err error)
	AgreeAndDerive(ctx context.Context, peerPublic crypto.PublicKey, alg AlgorithmID, kdf KDFParams) (derivedKey []byte, err error)
}
