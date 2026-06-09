package cryptoenginesv2

import "context"

// MAC
type MACer interface {
	KeyHandle
	MAC(ctx context.Context, message []byte) (mac []byte, err error)
	VerifyMAC(ctx context.Context, message, mac []byte) error
}
