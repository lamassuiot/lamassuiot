package softwarev2

import (
	"context"
	"errors"
	"sync"

	cryptoenginesv2 "github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines_v2"
)

// handleBase is embedded by every concrete handle. It carries the binding
// to the backend (for blob fetch + KEK unwrap), the public metadata, and
// the blob URI. It exposes the parts of kms.KeyHandle that are uniform
// across algorithms.
type handleBase struct {
	backend *Backend
	meta    cryptoenginesv2.KeyMetadata
	uri     string

	mu     sync.Mutex
	closed bool
}

func (h *handleBase) Metadata() cryptoenginesv2.KeyMetadata { return h.meta }
func (h *handleBase) BackendURI() string                    { return h.uri }

func (h *handleBase) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	return nil
}

func (h *handleBase) checkOpen() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return errors.New("soft: handle is closed")
	}
	return nil
}

// loadMaterial fetches the encrypted blob and unwraps it under the master
// KEK, returning the canonical bytes (PKCS#8, raw key, ML-KEM seed). The
// caller MUST zero the returned slice when done.
//
// This is the only path through which private material enters memory.
// All crypto ops in concrete handles call this exactly once per op.
func (h *handleBase) loadMaterial(ctx context.Context) ([]byte, error) {
	if err := h.checkOpen(); err != nil {
		return nil, err
	}

	keyMaterial, err := h.backend.blobs.ReadAll(ctx, h.uri)
	if err != nil {
		return nil, err
	}

	return keyMaterial, nil
}
