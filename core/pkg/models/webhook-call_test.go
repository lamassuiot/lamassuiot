package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
)

func TestWebhookCallHttpClientJSONRoundTrip(t *testing.T) {
	raw := `{
		"auth_mode": "jwt",
		"insecure_skip_verify": false,
		"call_timeout": "5s",
		"jwt_options": {"oidc_client_id": "id", "oidc_client_secret": "s3cret", "oidc_well_known": "https://idp/.well-known/openid-configuration"},
		"mtls_options": {"cert_content": "CERT", "key_content": "KEY"},
		"apikey_options": {"header": "X-API-Key", "key": "k"}
	}`

	var decoded WebhookCallHttpClient
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	stored, err := json.Marshal(decoded)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	var reloaded WebhookCallHttpClient
	if err := json.Unmarshal(stored, &reloaded); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if reloaded.AuthMode != config.JWT {
		t.Errorf("expected auth mode jwt, got %s", reloaded.AuthMode)
	}
	if reloaded.AuthJWTOptions.ClientSecret != "s3cret" {
		t.Errorf("expected client secret to survive storage, got %q (stored as %s)", reloaded.AuthJWTOptions.ClientSecret, stored)
	}
	if reloaded.AuthMTLSOptions.CertContent != "CERT" || reloaded.AuthMTLSOptions.KeyContent != "KEY" {
		t.Errorf("expected mtls content to survive storage, got %+v", reloaded.AuthMTLSOptions)
	}
	if reloaded.AuthApiKeyOptions.Header != "X-API-Key" || reloaded.AuthApiKeyOptions.Key != "k" {
		t.Errorf("expected api key options to survive storage, got %+v", reloaded.AuthApiKeyOptions)
	}
	if time.Duration(reloaded.CallTimeout) != 5*time.Second {
		t.Errorf("expected call timeout 5s, got %s", time.Duration(reloaded.CallTimeout))
	}
}
