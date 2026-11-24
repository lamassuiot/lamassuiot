package helpers_test

import (
	"strings"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/stretchr/testify/require"
)

// A key is addressed by its id (a UUID) or its digest (64 hex characters) before anything else, so what has
// either shape must never be taken for an alias.
func TestKeyIdentifierShapes(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	uuid := "0190a6c4-7f3e-7b2a-9c1d-3e5f6a7b8c9d"

	for name, tc := range map[string]struct {
		in           string
		isUUID, isHx bool
	}{
		"canonical uuid":          {uuid, true, false},
		"uppercase uuid":          {strings.ToUpper(uuid), true, false},
		"digest":                  {digest, false, true},
		"uppercase digest":        {strings.ToUpper(digest), false, true},
		"uuid without hyphens":    {strings.ReplaceAll(uuid, "-", ""), false, false},
		"braced uuid":             {"{" + uuid + "}", false, false},
		"uuid with a suffix":      {uuid + "x", false, false},
		"sha-1 ski (40 hex)":      {strings.Repeat("ab", 20), false, false},
		"digest, one char short":  {digest[1:], false, false},
		"digest, one char longer": {digest + "a", false, false},
		"digest with a non-hex":   {digest[:63] + "g", false, false},
		"an ordinary alias":       {"signing-key-prod", false, false},
		"empty":                   {"", false, false},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.isUUID, helpers.IsKeyUUID(tc.in), "IsKeyUUID")
			require.Equal(t, tc.isHx, helpers.IsKeyDigest(tc.in), "IsKeyDigest")
		})
	}
}
