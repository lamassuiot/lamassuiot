package cryptoenginesv2

import "context"

// Wrap
type KeyWrapper interface {
	KeyHandle
	WrapKey(ctx context.Context, keyMaterial []byte, opts WrapOpts) (wrapped []byte, err error)
	UnwrapKey(ctx context.Context, wrapped []byte, opts WrapOpts) (keyMaterial []byte, err error)
}
