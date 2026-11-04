package helpers

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodeJWTPayload(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user-1","admin":true}`))
	claims, err := DecodeJWTPayload("header." + payload + ".signature")
	require.NoError(t, err)
	require.Equal(t, "user-1", claims["sub"])
	require.Equal(t, true, claims["admin"])
}

func TestDecodeJWTPayloadRejectsMalformedTokens(t *testing.T) {
	for _, token := range []string{"", "one.two", "a.!invalid!.c", "a." + base64.RawURLEncoding.EncodeToString([]byte("not-json")) + ".c"} {
		_, err := DecodeJWTPayload(token)
		require.Error(t, err, token)
	}
}
