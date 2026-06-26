package helpers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// DecodeJWTPayload extracts the claims from a JWT token by base64-decoding the
// payload segment without verifying the signature. This is safe for non-auth
// purposes such as logging context enrichment and identity extraction — the
// caller must NOT use the returned claims for access-control decisions.
func DecodeJWTPayload(token string) (map[string]interface{}, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a JWT: expected 3 dot-separated segments")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode JWT payload: %w", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal JWT payload: %w", err)
	}
	return claims, nil
}
