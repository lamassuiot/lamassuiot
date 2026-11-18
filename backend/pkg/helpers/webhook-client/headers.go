package webhookclient

import (
	"net/textproto"
	"strings"
)

// reservedHeaders are identity, routing and transport headers set by the
// gateway or by internal services. A user-configured API key header must never
// carry them: receiving services treat them as trusted (e.g.
// X-Principal-ID: admin-mode bypasses authorization).
var reservedHeaders = map[string]struct{}{
	"X-Principal-Id":         {},
	"X-Request-Id":           {},
	"Ssl-Client-Cert":        {},
	"X-Amzn-Mtls-Clientcert": {},
	"X-Original-Uri":         {},
	"X-Real-Ip":              {},
	"Forwarded":              {},
	"Host":                   {},
	"Content-Type":           {},
	"Content-Length":         {},
	"Transfer-Encoding":      {},
}

// reservedHeaderPrefixes cover header families owned by proxies and the
// platform (X-Forwarded-Cert, X-Forwarded-Tls-Client-Cert, X-Lms-Source,
// X-Envoy-Original-Path, ...).
var reservedHeaderPrefixes = []string{"X-Forwarded-", "X-Envoy-", "X-Lms-"}

func isReservedHeader(name string) bool {
	canonical := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(name))
	if _, reserved := reservedHeaders[canonical]; reserved {
		return true
	}
	for _, prefix := range reservedHeaderPrefixes {
		if strings.HasPrefix(canonical, prefix) {
			return true
		}
	}
	return false
}
