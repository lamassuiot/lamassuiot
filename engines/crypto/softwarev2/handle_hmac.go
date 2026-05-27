package softwarev2

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"

	cryptoenginesv2 "github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines_v2"
)

// hmacHandle implements cryptoenginesv2.MACer for HMAC-SHA-{256,384,512} keys.
type hmacHandle struct {
	handleBase
}

func (h *hmacHandle) hashFunc() (func() hash.Hash, error) {
	switch h.meta.Algorithm {
	case "HMAC_SHA_256":
		return sha256.New, nil
	case "HMAC_SHA_384":
		return sha512.New384, nil
	case "HMAC_SHA_512":
		return sha512.New, nil
	}
	return nil, fmt.Errorf("soft: unsupported HMAC algorithm %s", h.meta.Algorithm)
}

func (h *hmacHandle) MAC(ctx context.Context, message []byte) ([]byte, error) {
	newHash, err := h.hashFunc()
	if err != nil {
		return nil, err
	}
	key, err := h.loadMaterial(ctx)
	if err != nil {
		return nil, err
	}
	defer zero(key)

	mac := hmac.New(newHash, key)
	mac.Write(message)
	return mac.Sum(nil), nil
}

func (h *hmacHandle) VerifyMAC(ctx context.Context, message, expected []byte) error {
	computed, err := h.MAC(ctx, message)
	if err != nil {
		return err
	}
	if !hmac.Equal(computed, expected) {
		return errors.New("soft: HMAC verification failed")
	}
	return nil
}

// ensure hmacHandle satisfies the MACer interface at compile time.
var _ cryptoenginesv2.MACer = (*hmacHandle)(nil)
