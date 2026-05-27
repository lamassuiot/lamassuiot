package registry

import (
	"fmt"
	"sort"
	"sync"

	cryptoenginesv2 "github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines_v2"
)

// staticRegistry is the default Registry implementation: a compiled-in map.
// It is safe for concurrent reads and frozen after construction.
type staticRegistry struct {
	algos map[cryptoenginesv2.AlgorithmID]cryptoenginesv2.AlgorithmSpec
	once  sync.Once
	ids   []cryptoenginesv2.AlgorithmID // cached sorted IDs for List()
}

// NewStaticRegistry builds a registry from an explicit list of specs. The
// builtin registry uses this with the canonical table; tests may use it
// with a subset.
//
// Duplicate IDs panic at construction — registries are static so this is
// always a programmer error caught at startup.
func NewStaticRegistry(specs []cryptoenginesv2.AlgorithmSpec) cryptoenginesv2.Registry {
	r := &staticRegistry{
		algos: make(map[cryptoenginesv2.AlgorithmID]cryptoenginesv2.AlgorithmSpec, len(specs)),
	}
	for _, s := range specs {
		if _, dup := r.algos[s.ID]; dup {
			panic(fmt.Sprintf("kms: duplicate algorithm registration: %s", s.ID))
		}
		r.algos[s.ID] = s
	}
	return r
}

func (r *staticRegistry) Get(id cryptoenginesv2.AlgorithmID) (cryptoenginesv2.AlgorithmSpec, error) {
	spec, ok := r.algos[id]
	if !ok {
		return cryptoenginesv2.AlgorithmSpec{}, fmt.Errorf("%w: %q", cryptoenginesv2.ErrAlgorithmNotSupported, id)
	}
	return spec, nil
}

func (r *staticRegistry) List() []cryptoenginesv2.AlgorithmSpec {
	r.once.Do(func() {
		r.ids = make([]cryptoenginesv2.AlgorithmID, 0, len(r.algos))
		for id := range r.algos {
			r.ids = append(r.ids, id)
		}
		sort.Slice(r.ids, func(i, j int) bool { return r.ids[i] < r.ids[j] })
	})
	out := make([]cryptoenginesv2.AlgorithmSpec, len(r.ids))
	for i, id := range r.ids {
		out[i] = r.algos[id]
	}
	return out
}

func (r *staticRegistry) SupportsOperation(id cryptoenginesv2.AlgorithmID, op cryptoenginesv2.Operation) bool {
	spec, ok := r.algos[id]
	if !ok {
		return false
	}
	return containsOp(spec.Operations, op)
}

func (r *staticRegistry) SupportsLegacyOperation(id cryptoenginesv2.AlgorithmID, op cryptoenginesv2.Operation) bool {
	spec, ok := r.algos[id]
	if !ok {
		return false
	}
	return containsOp(spec.LegacyOperations, op)
}

func containsOp(ops []cryptoenginesv2.Operation, target cryptoenginesv2.Operation) bool {
	for _, o := range ops {
		if o == target {
			return true
		}
	}
	return false
}
