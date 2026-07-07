package cryptoenginesv2

import "context"

// MAC. alg selects the MAC algorithm (e.g. HMAC_SHA_256) and must be
// compatible with the key's KeySpec.
type MACer interface {
	KeyHandle
	MAC(ctx context.Context, message []byte, alg AlgorithmID) (mac []byte, err error)
	VerifyMAC(ctx context.Context, message, mac []byte, alg AlgorithmID) error
}
