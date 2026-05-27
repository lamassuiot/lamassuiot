package backendregistry

import (
	cryptoenginesv2 "github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines_v2"
)

// backendSupports reports whether a backend's declared Capabilities
// include the given algorithm. It is intentionally O(N) on the
// algorithms list: backends declare a finite, small set (~30) and this
// check runs once per CreateKey call.
func backendSupports(b cryptoenginesv2.Backend, alg cryptoenginesv2.AlgorithmID) bool {
	caps := b.Capabilities()
	for _, a := range caps.Algorithms {
		if a == alg {
			return true
		}
	}
	return false
}
