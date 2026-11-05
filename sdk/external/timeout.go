package external_clients

import "time"

// revocationRequestTimeout bounds each OCSP/CRL request, including connection, TLS handshake and reading the body.
// Callers try several endpoints in turn and fail closed, so a hanging server must not block them indefinitely.
var revocationRequestTimeout = 10 * time.Second
