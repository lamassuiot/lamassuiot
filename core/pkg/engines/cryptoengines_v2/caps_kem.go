package cryptoenginesv2

import (
	"context"
	"crypto"
)

// KEM
type Encapsulator interface {
	KeyHandle
	crypto.Encapsulator
	EncapsulateContext(ctx context.Context) (sharedSecret, ciphertext []byte, err error)
}

type Decapsulator interface {
	KeyHandle
	crypto.Decapsulator
	DecapsulateContext(ctx context.Context, ciphertext []byte) (sharedSecret []byte, err error)
}
