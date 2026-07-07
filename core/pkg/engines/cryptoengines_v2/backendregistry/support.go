package backendregistry

import (
	cryptoenginesv2 "github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines_v2"
)

// backendSupports reports whether a backend's declared Capabilities
// include the given key spec. It is intentionally O(N) on the KeySpecs
// list: backends declare a finite, small set and this check runs once per
// CreateKey call.
func backendSupports(b cryptoenginesv2.Backend, spec cryptoenginesv2.KeySpec) bool {
	caps := b.Capabilities()
	for _, s := range caps.KeySpecs {
		if s == spec {
			return true
		}
	}
	return false
}
