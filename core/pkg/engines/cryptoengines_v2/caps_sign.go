package cryptoenginesv2

import (
	"context"
	"crypto"
)

// Signing
type Signer interface {
	KeyHandle
	crypto.Signer
	SignContext(ctx context.Context, data []byte, opts crypto.SignerOpts) ([]byte, error)
}

type MessageSigner interface {
	Signer
	crypto.MessageSigner
	SignMessageContext(ctx context.Context, msg []byte, opts crypto.SignerOpts) ([]byte, error)
}

type Verifier interface {
	KeyHandle
	Verify(ctx context.Context, data, signature []byte, opts crypto.SignerOpts) error
}
