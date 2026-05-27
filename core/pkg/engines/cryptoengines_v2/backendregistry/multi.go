package backendregistry

import (
	"fmt"

	cryptoenginesv2 "github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines_v2"
)

// multiRegistry routes by BackendHint when provided; otherwise picks the
// first registered backend that supports the requested algorithm.
//
// Selection strategy when no BackendHint is given:
//  1. Iterate backends in registration order.
//  2. Pick the first whose Capabilities() include the spec.Algorithm.
//  3. If none qualifies, return an error.
//
// "Registration order" matters: register the higher-assurance backend
// (HSM/PKCS#11) before the lower-assurance one (soft) so that, absent a
// hint, sensitive keys land on the safer backend.
type multiRegistry struct {
	order  []string // names in registration order
	byName map[string]cryptoenginesv2.Backend
}

// NewMultiBackendRegistry constructs a multi-backend registry. Backends
// are searched in the order given when no BackendHint is provided.
func NewMultiBackendRegistry(backends ...cryptoenginesv2.Backend) cryptoenginesv2.BackendRegistry {
	r := &multiRegistry{
		order:  make([]string, 0, len(backends)),
		byName: make(map[string]cryptoenginesv2.Backend, len(backends)),
	}
	for _, b := range backends {
		if b == nil {
			panic("backendregistry: nil backend in NewMultiBackendRegistry")
		}
		name := b.Name()
		if _, dup := r.byName[name]; dup {
			panic(fmt.Sprintf("backendregistry: duplicate backend name %q", name))
		}
		r.byName[name] = b
		r.order = append(r.order, name)
	}
	return r
}

func (r *multiRegistry) Lookup(name string) (cryptoenginesv2.Backend, error) {
	b, ok := r.byName[name]
	if !ok {
		return nil, fmt.Errorf("backendregistry: no backend named %q (known: %v)", name, r.order)
	}
	return b, nil
}

func (r *multiRegistry) Select(spec cryptoenginesv2.CreateKeySpec) (cryptoenginesv2.Backend, error) {
	if hint := spec.BackendHint; hint != "" {
		b, err := r.Lookup(hint)
		if err != nil {
			return nil, err
		}
		if !backendSupports(b, spec.Algorithm) {
			return nil, fmt.Errorf("backendregistry: backend %q (hinted) does not support algorithm %q",
				hint, spec.Algorithm)
		}
		return b, nil
	}

	for _, name := range r.order {
		b := r.byName[name]
		if backendSupports(b, spec.Algorithm) {
			return b, nil
		}
	}
	return nil, fmt.Errorf("backendregistry: no backend supports algorithm %q (tried %v)",
		spec.Algorithm, r.order)
}

func (r *multiRegistry) List() []cryptoenginesv2.Backend {
	out := make([]cryptoenginesv2.Backend, 0, len(r.order))
	for _, name := range r.order {
		out = append(out, r.byName[name])
	}
	return out
}
