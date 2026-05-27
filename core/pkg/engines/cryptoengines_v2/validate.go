package cryptoenginesv2

import (
	"fmt"
)

// validateOpsAgainstAlgorithm checks that every operation requested in a
// CreateKey / ImportKey spec is permitted by the algorithm's spec in the
// registry.
//
// Rules:
//   - An empty 'requested' list means "use the algorithm's default operations"
//     (alg.Operations) and is accepted.
//   - Every requested op MUST appear in alg.Operations. Legacy operations
//     (alg.LegacyOperations) are NOT acceptable at key-creation time: a key
//     created today must use the algorithm in normal mode. Legacy ops are
//     a runtime concession for consuming old data, not a way to provision
//     keys.
//   - Duplicate ops in the request are silently deduplicated (not an error,
//     but the resulting metadata holds the deduped list).
//
// Returns ErrOperationNotAllowed wrapping a descriptive message on failure.
func validateOpsAgainstAlgorithm(alg AlgorithmSpec, requested []Operation) error {
	if len(requested) == 0 {
		// Caller did not narrow; accept defaults.
		return nil
	}

	allowed := make(map[Operation]struct{}, len(alg.Operations))
	for _, op := range alg.Operations {
		allowed[op] = struct{}{}
	}

	for _, op := range requested {
		if _, ok := allowed[op]; !ok {
			return fmt.Errorf("%w: algorithm %q does not permit operation %q in normal mode (allowed: %v)",
				ErrOperationNotAllowed, alg.ID, op, alg.Operations)
		}
	}
	return nil
}
