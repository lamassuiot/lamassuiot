package softwarev2

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	cryptoenginesv2 "github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines_v2"
)

// hmacHandle implements cryptoenginesv2.MACer for HMAC-SHA-{256,384,512} keys.
type hmacHandle struct {
	*handleBase
}

func (h *hmacHandle) hashFunc(alg cryptoenginesv2.AlgorithmID) (func() hash.Hash, error) {
	switch alg {
	case cryptoenginesv2.AlgHMACSHA256:
		return sha256.New, nil
	case cryptoenginesv2.AlgHMACSHA384:
		return sha512.New384, nil
	case cryptoenginesv2.AlgHMACSHA512:
		return sha512.New, nil
	}
	return nil, fmt.Errorf("soft: unsupported HMAC algorithm %s", alg)
}

func (h *hmacHandle) MAC(ctx context.Context, message []byte, alg cryptoenginesv2.AlgorithmID) ([]byte, error) {
	newHash, err := h.hashFunc(alg)
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

func (h *hmacHandle) VerifyMAC(ctx context.Context, message, expected []byte, alg cryptoenginesv2.AlgorithmID) error {
	computed, err := h.MAC(ctx, message, alg)
	if err != nil {
		return err
	}
	if !hmac.Equal(computed, expected) {
		return fmt.Errorf("soft: HMAC verification failed: %w", cryptoenginesv2.ErrVerificationFailed)
	}
	return nil
}

// ensure hmacHandle satisfies the MACer interface at compile time.
var _ cryptoenginesv2.MACer = (*hmacHandle)(nil)
