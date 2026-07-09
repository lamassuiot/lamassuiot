package pkg

import (
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
)

func TestMonolithicAuthzProxyAuthorizeForwardsOriginalRequestAndRestoresBody(t *testing.T) {
	const requestBody = `{"clientId":"device-1"}`
	seen := make(chan capturedAuthzRequest, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read authz body: %v", err)
		}
		seen <- capturedAuthzRequest{
			method:       r.Method,
			path:         r.URL.Path,
			rawQuery:     r.URL.RawQuery,
			originalPath: r.Header.Get("x-envoy-original-path"),
			authHeader:   r.Header.Get("authorization"),
			body:         string(body),
		}

		w.Header().Set("x-current-user", "device-1")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	port, err := strconv.Atoi(serverURL.Port())
	if err != nil {
		t.Fatalf("parse server port: %v", err)
	}

	proxy := newMonolithicAuthzProxy(port, []string{"/api/wfx/"})
	req := httptest.NewRequest(http.MethodPut, "https://localhost/api/wfx/sbi/v1/jobs/job-1/status?trace=true", strings.NewReader(requestBody))
	req.Header.Set("authorization", "Bearer token")

	status, err := proxy.authorize(req)
	if err != nil {
		t.Fatalf("authorize returned error: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, status)
	}

	captured := <-seen
	if captured.method != http.MethodPut {
		t.Fatalf("expected method %s, got %s", http.MethodPut, captured.method)
	}
	if captured.path != "/v1/ext_authz/check/api/wfx/sbi/v1/jobs/job-1/status" {
		t.Fatalf("unexpected authz path: %s", captured.path)
	}
	if captured.rawQuery != "trace=true" {
		t.Fatalf("unexpected raw query: %s", captured.rawQuery)
	}
	if captured.originalPath != "/api/wfx/sbi/v1/jobs/job-1/status?trace=true" {
		t.Fatalf("unexpected original path header: %s", captured.originalPath)
	}
	if captured.authHeader != "Bearer token" {
		t.Fatalf("unexpected authorization header: %s", captured.authHeader)
	}
	if captured.body != requestBody {
		t.Fatalf("unexpected authz body: %s", captured.body)
	}
	if req.Header.Get("x-current-user") != "device-1" {
		t.Fatalf("x-current-user was not propagated")
	}
	if req.Header.Get("x-principal-id") != "device-1" {
		t.Fatalf("x-principal-id was not propagated")
	}

	restoredBody, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read restored body: %v", err)
	}
	if string(restoredBody) != requestBody {
		t.Fatalf("body was not restored, got: %s", string(restoredBody))
	}
}

func TestAuthzProxyPrefixesDefaultToWFXWhenWFXIsEnabled(t *testing.T) {
	prefixes := authzProxyPrefixes(MonolithicConfig{WfxNorthPort: 9081})
	if len(prefixes) != 2 {
		t.Fatalf("expected default WFX prefixes, got %v", prefixes)
	}
	if prefixes[0] != "/api/wfx/nbi/" || prefixes[1] != "/api/wfx/sbi/" {
		t.Fatalf("unexpected default WFX prefixes: %v", prefixes)
	}
}

func TestAuthzProxyPrefixesCanBeExplicitlyDisabled(t *testing.T) {
	prefixes := authzProxyPrefixes(MonolithicConfig{
		WfxNorthPort:       9081,
		AuthzProxyPrefixes: []string{},
	})
	if len(prefixes) != 0 {
		t.Fatalf("expected no authz proxy prefixes, got %v", prefixes)
	}
}

func TestEnvoyStyleClientCertHeaderIncludesCertAndChain(t *testing.T) {
	key, err := chelpers.GenerateRSAKey(2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	crt, err := chelpers.GenerateSelfSignedCertificate(key, "device-1")
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	header := envoyStyleClientCertHeader([]*x509.Certificate{crt})
	if !strings.Contains(header, "Cert=") {
		t.Fatalf("expected Cert in XFCC header: %s", header)
	}
	if !strings.Contains(header, "Chain=") {
		t.Fatalf("expected Chain in XFCC header: %s", header)
	}

	leafPEM := decodeXFCCPart(t, header, "Cert")
	if !strings.Contains(leafPEM, "BEGIN CERTIFICATE") {
		t.Fatalf("decoded Cert value does not contain PEM certificate")
	}
}

type capturedAuthzRequest struct {
	method       string
	path         string
	rawQuery     string
	originalPath string
	authHeader   string
	body         string
}

func decodeXFCCPart(t *testing.T, header, key string) string {
	t.Helper()
	for _, part := range strings.Split(header, ";") {
		part = strings.TrimSpace(part)
		prefix := key + "="
		if !strings.HasPrefix(part, prefix) {
			continue
		}
		escaped := strings.Trim(strings.TrimPrefix(part, prefix), `"`)
		decoded, err := url.QueryUnescape(escaped)
		if err != nil {
			t.Fatalf("decode %s XFCC part: %v", key, err)
		}
		return decoded
	}
	t.Fatalf("missing %s XFCC part in %s", key, header)
	return ""
}
