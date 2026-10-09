package tests

import (
	"crypto/tls"
	"net/http"
)

// adminModeTransport wraps any RoundTripper and injects the X-Principal-ID: admin-mode
// header on every request, bypassing authz middleware enforcement in test servers.
type adminModeTransport struct {
	base http.RoundTripper
}

func (t *adminModeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set("X-Principal-ID", "admin-mode")
	return t.base.RoundTrip(clone)
}

// NewTestHTTPClient returns an *http.Client that automatically adds the admin-mode
// bypass header to every request. Pass an optional base transport to layer on top of
// (e.g. a *http.Transport with a custom TLSClientConfig); defaults to http.DefaultTransport.
func NewTestHTTPClient(base ...http.RoundTripper) *http.Client {
	var baseTransport http.RoundTripper = http.DefaultTransport
	if len(base) > 0 && base[0] != nil {
		baseTransport = base[0]
	}
	return &http.Client{
		Transport: &adminModeTransport{base: baseTransport},
	}
}

// NewTestHTTPClientInsecure returns a test HTTP client that skips TLS verification
// in addition to injecting the admin-mode bypass header.
func NewTestHTTPClientInsecure() *http.Client {
	return NewTestHTTPClient(&http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // #nosec G402 — test-only
		},
	})
}
