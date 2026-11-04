package helpers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// DecodeJWTPayload decodes JWT claims without verifying the signature. Callers must
// not use the returned claims for access-control decisions.
func DecodeJWTPayload(token string) (map[string]any, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a JWT: expected 3 dot-separated segments")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid JWT payload encoding: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("invalid JWT payload JSON: %w", err)
	}
	return claims, nil
}
