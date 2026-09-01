package registry

import (
	"fmt"
	"sort"
	"sync"

	cryptoenginesv2 "github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines_v2"
)

// staticRegistry is the default Registry implementation: two compiled-in maps
// (KeySpec -> info, AlgorithmID -> info). Safe for concurrent reads and frozen
// after construction.
type staticRegistry struct {
	specs map[cryptoenginesv2.KeySpec]cryptoenginesv2.KeySpecInfo
	algos map[cryptoenginesv2.AlgorithmID]cryptoenginesv2.AlgorithmInfo

	once    sync.Once
	specIDs []cryptoenginesv2.KeySpec     // cached sorted spec IDs
	algoIDs []cryptoenginesv2.AlgorithmID // cached sorted algorithm IDs
}

// NewStaticRegistry builds a registry from explicit KeySpec and algorithm
// tables. The builtin registry uses this with the canonical catalog; tests may
// use it with a subset.
//
// Duplicate IDs panic at construction — registries are static so this is
// always a programmer error caught at startup.
func NewStaticRegistry(specs []cryptoenginesv2.KeySpecInfo, algos []cryptoenginesv2.AlgorithmInfo) cryptoenginesv2.Registry {
	r := &staticRegistry{
		specs: make(map[cryptoenginesv2.KeySpec]cryptoenginesv2.KeySpecInfo, len(specs)),
		algos: make(map[cryptoenginesv2.AlgorithmID]cryptoenginesv2.AlgorithmInfo, len(algos)),
	}
	for _, s := range specs {
		if _, dup := r.specs[s.KeySpec]; dup {
			panic(fmt.Sprintf("kms: duplicate key spec registration: %s", s.KeySpec))
		}
		r.specs[s.KeySpec] = s
	}
	for _, a := range algos {
		if _, dup := r.algos[a.ID]; dup {
			panic(fmt.Sprintf("kms: duplicate algorithm registration: %s", a.ID))
		}
		r.algos[a.ID] = a
	}
	return r
}

func (r *staticRegistry) GetKeySpec(spec cryptoenginesv2.KeySpec) (cryptoenginesv2.KeySpecInfo, error) {
	info, ok := r.specs[spec]
	if !ok {
		return cryptoenginesv2.KeySpecInfo{}, fmt.Errorf("%w: %q", cryptoenginesv2.ErrKeySpecNotSupported, spec)
	}
	return info, nil
}

func (r *staticRegistry) GetAlgorithm(id cryptoenginesv2.AlgorithmID) (cryptoenginesv2.AlgorithmInfo, error) {
	info, ok := r.algos[id]
	if !ok {
		return cryptoenginesv2.AlgorithmInfo{}, fmt.Errorf("%w: %q", cryptoenginesv2.ErrAlgorithmNotSupported, id)
	}
	return info, nil
}

func (r *staticRegistry) cacheIDs() {
	r.once.Do(func() {
		r.specIDs = make([]cryptoenginesv2.KeySpec, 0, len(r.specs))
		for id := range r.specs {
			r.specIDs = append(r.specIDs, id)
		}
		sort.Slice(r.specIDs, func(i, j int) bool { return r.specIDs[i] < r.specIDs[j] })

		r.algoIDs = make([]cryptoenginesv2.AlgorithmID, 0, len(r.algos))
		for id := range r.algos {
			r.algoIDs = append(r.algoIDs, id)
		}
		sort.Slice(r.algoIDs, func(i, j int) bool { return r.algoIDs[i] < r.algoIDs[j] })
	})
}

func (r *staticRegistry) ListKeySpecs() []cryptoenginesv2.KeySpecInfo {
	r.cacheIDs()
	out := make([]cryptoenginesv2.KeySpecInfo, len(r.specIDs))
	for i, id := range r.specIDs {
		out[i] = r.specs[id]
	}
	return out
}

func (r *staticRegistry) ListAlgorithms() []cryptoenginesv2.AlgorithmInfo {
	r.cacheIDs()
	out := make([]cryptoenginesv2.AlgorithmInfo, len(r.algoIDs))
	for i, id := range r.algoIDs {
		out[i] = r.algos[id]
	}
	return out
}

func (r *staticRegistry) AlgorithmsFor(spec cryptoenginesv2.KeySpec, op cryptoenginesv2.Operation) []cryptoenginesv2.AlgorithmID {
	r.cacheIDs()
	var out []cryptoenginesv2.AlgorithmID
	for _, id := range r.algoIDs { // sorted for stable output
		a := r.algos[id]
		if containsOp(a.Operations, op) && containsSpec(a.CompatibleKeySpecs, spec) {
			out = append(out, id)
		}
	}
	return out
}

func (r *staticRegistry) ValidateAlgorithm(spec cryptoenginesv2.KeySpec, op cryptoenginesv2.Operation, alg cryptoenginesv2.AlgorithmID) error {
	a, ok := r.algos[alg]
	if !ok {
		return fmt.Errorf("%w: %q", cryptoenginesv2.ErrAlgorithmNotSupported, alg)
	}
	if !containsOp(a.Operations, op) {
		return fmt.Errorf("%w: algorithm %q does not perform operation %q", cryptoenginesv2.ErrOperationNotAllowed, alg, op)
	}
	if !containsSpec(a.CompatibleKeySpecs, spec) {
		return fmt.Errorf("%w: algorithm %q is not valid for key spec %q", cryptoenginesv2.ErrOperationNotAllowed, alg, spec)
	}
	return nil
}

func containsOp(ops []cryptoenginesv2.Operation, target cryptoenginesv2.Operation) bool {
	for _, o := range ops {
		if o == target {
			return true
		}
	}
	return false
}

func containsSpec(specs []cryptoenginesv2.KeySpec, target cryptoenginesv2.KeySpec) bool {
	for _, s := range specs {
		if s == target {
			return true
		}
	}
	return false
}
