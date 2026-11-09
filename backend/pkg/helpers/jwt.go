package helpers

import (
	corehelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
)

// DecodeJWTPayload extracts the claims from a JWT token by base64-decoding the
// payload segment without verifying the signature. This is safe for non-auth
// purposes such as logging context enrichment and identity extraction — the
// caller must NOT use the returned claims for access-control decisions.
func DecodeJWTPayload(token string) (map[string]any, error) {
	return corehelpers.DecodeJWTPayload(token)
}
