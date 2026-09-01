package cryptoenginesv2

import (
	"fmt"
)

// validateOpsAgainstKeySpec checks that every operation requested in a
// CreateKey / ImportKey spec is supported by the KeySpec's material.
//
// Rules:
//   - An empty 'requested' list means "authorize the KeySpec's full supported
//     set" (info.SupportedOperations) and is accepted.
//   - Every requested op MUST appear in info.SupportedOperations.
//   - Duplicate ops in the request are tolerated (the caller is responsible for
//     the final persisted set).
//
// Returns ErrOperationNotAllowed wrapping a descriptive message on failure.
func validateOpsAgainstKeySpec(info KeySpecInfo, requested []Operation) error {
	if len(requested) == 0 {
		return nil // caller did not narrow; accept the KeySpec's defaults
	}

	allowed := make(map[Operation]struct{}, len(info.SupportedOperations))
	for _, op := range info.SupportedOperations {
		allowed[op] = struct{}{}
	}

	for _, op := range requested {
		if _, ok := allowed[op]; !ok {
			return fmt.Errorf("%w: key spec %q does not support operation %q (supported: %v)",
				ErrOperationNotAllowed, info.KeySpec, op, info.SupportedOperations)
		}
	}
	return nil
}

// resolveOperations computes the authorized operation set for a new key:
// the deduplicated union of explicit ops and the expansion of any coarse
// usages. When both are empty, it defaults to the KeySpec's full supported set.
func resolveOperations(info KeySpecInfo, explicit []Operation, usages []KeyUsage) []Operation {
	seen := make(map[Operation]struct{})
	out := make([]Operation, 0, len(explicit)+len(usages)*2)
	add := func(ops []Operation) {
		for _, op := range ops {
			if _, dup := seen[op]; dup {
				continue
			}
			seen[op] = struct{}{}
			out = append(out, op)
		}
	}
	add(explicit)
	add(ExpandUsages(usages))
	if len(out) == 0 {
		return append([]Operation(nil), info.SupportedOperations...)
	}
	return out
}
