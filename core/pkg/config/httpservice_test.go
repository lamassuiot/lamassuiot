package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

const (
	testCertPEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	testKeyPEM  = "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n"
)

func TestAuthMTLSOptionsContentPEM(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString

	for name, opts := range map[string]AuthMTLSOptions{
		"base64 PEM":             {CertContent: b64([]byte(testCertPEM)), KeyContent: b64([]byte(testKeyPEM))},
		"base64 PEM with spaces": {CertContent: " " + b64([]byte(testCertPEM)) + "\n", KeyContent: b64([]byte(testKeyPEM))},
		"plain PEM":              {CertContent: testCertPEM, KeyContent: testKeyPEM},
	} {
		t.Run(name, func(t *testing.T) {
			cert, key, err := opts.ContentPEM()
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if string(cert) != testCertPEM || string(key) != testKeyPEM {
				t.Fatalf("unexpected PEM: cert=%q key=%q", cert, key)
			}
		})
	}

	for name, tc := range map[string]struct {
		opts AuthMTLSOptions
		err  string
	}{
		"invalid base64 cert": {AuthMTLSOptions{CertContent: "not base64!", KeyContent: testKeyPEM}, "mtls_options.cert_content must be base64-encoded PEM"},
		"base64 without PEM":  {AuthMTLSOptions{CertContent: testCertPEM, KeyContent: b64([]byte("raw key bytes"))}, "mtls_options.key_content must be base64-encoded PEM"},
		"file path":           {AuthMTLSOptions{CertContent: "/etc/certs/client.crt", KeyContent: testKeyPEM}, "mtls_options.cert_content must be base64-encoded PEM"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := tc.opts.ContentPEM()
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("expected error containing %q, got %v", tc.err, err)
			}
		})
	}
}
