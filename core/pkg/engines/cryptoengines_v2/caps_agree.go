package cryptoenginesv2

import (
	"context"
	"crypto"
)

// Key agreement
type KeyAgreementer interface {
	KeyHandle
	Agree(ctx context.Context, peerPublic crypto.PublicKey) (sharedSecret []byte, err error)
	AgreeAndDerive(ctx context.Context, peerPublic crypto.PublicKey, kdf KDFParams) (derivedKey []byte, err error)
}
