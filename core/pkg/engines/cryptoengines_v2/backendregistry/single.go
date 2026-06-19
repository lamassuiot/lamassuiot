package backendregistry

// Package backendregistry provides BackendRegistry implementations.
//
//   - singleRegistry: wraps exactly one backend; useful for dev, tests,
//     and deployments where only one backend is provisioned.
//   - multiRegistry:  routes by BackendHint, falling back to capability-based
//     selection. Use this in production setups with heterogeneous backends.

import (
	"fmt"

	cryptoenginesv2 "github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines_v2"
)

// singleRegistry serves a single backend regardless of any BackendHint
// in the spec. It is the simplest registry and the right choice when
// there is only one backend wired up.
type singleRegistry struct {
	backend cryptoenginesv2.Backend
}

// NewSingleBackendRegistry returns a BackendRegistry that always returns
// the given backend.
func NewSingleBackendRegistry(b cryptoenginesv2.Backend) cryptoenginesv2.BackendRegistry {
	if b == nil {
		panic("backendregistry: NewSingleBackendRegistry called with nil backend")
	}
	return &singleRegistry{backend: b}
}

func (r *singleRegistry) Lookup(name string) (cryptoenginesv2.Backend, error) {
	if name == r.backend.Name() {
		return r.backend, nil
	}
	return nil, fmt.Errorf("backendregistry: no backend named %q (only %q is configured)",
		name, r.backend.Name())
}

func (r *singleRegistry) Select(spec cryptoenginesv2.CreateKeySpec) (cryptoenginesv2.Backend, error) {
	// If the caller hinted a backend, it must match the one we have.
	if spec.BackendHint != "" && spec.BackendHint != r.backend.Name() {
		return nil, fmt.Errorf("backendregistry: BackendHint=%q does not match the only configured backend %q",
			spec.BackendHint, r.backend.Name())
	}
	// Validate algorithm capability up-front so the error is clear at the
	// registry level rather than deep inside the backend.
	if !backendSupports(r.backend, spec.Algorithm) {
		return nil, fmt.Errorf("backendregistry: backend %q does not support algorithm %q",
			r.backend.Name(), spec.Algorithm)
	}
	return r.backend, nil
}

func (r *singleRegistry) List() []cryptoenginesv2.Backend {
	return []cryptoenginesv2.Backend{r.backend}
}
