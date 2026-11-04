package ca

// A CA certificate and its key generated with OpenSSL (prime256v1, "subjectKeyIdentifier=hash"):
//
//	openssl ecparam -genkey -name prime256v1 -noout | openssl pkcs8 -topk8 -nocrypt -out ca.key
//	openssl req -x509 -new -key ca.key -subj "/CN=OpenSSL Imported CA" -days 36500 \
//	  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
//	  -addext "subjectKeyIdentifier=hash" -out ca.pem
//
// OpenSSL derives the SKI from the SHA-1 of the public key (RFC 5280 method 1), so it differs from the
// key ID Lamassu's crypto engines use, the SHA-256 of the SubjectPublicKeyInfo. Both were computed
// with OpenSSL.
const (
	opensslCACertPEM = `-----BEGIN CERTIFICATE-----
MIIBgTCCASigAwIBAgIUCPQRT6SuwOkuAVeaLd+LgA/7HkQwCgYIKoZIzj0EAwIw
HjEcMBoGA1UEAwwTT3BlblNTTCBJbXBvcnRlZCBDQTAgFw0yNjEwMjcxMDQ0MDla
GA8yMTI2MTAwMzEwNDQwOVowHjEcMBoGA1UEAwwTT3BlblNTTCBJbXBvcnRlZCBD
QTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJzIjanyOCVIJwY46B8iXR8XbzaV
j9A1n23BgLwUO2NWrCHXa+MUozO975xha++CRPevwLxrpo3RTQ6/urJAwNGjQjBA
MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSCRC8y
tg6EneTSBktiFjOulUw1xzAKBggqhkjOPQQDAgNHADBEAiBrJxexbmb4CrLAAh6n
+XRHkIaUrNiTUxD1JZCg2lfULQIgPr82ONEs+SBY1AqvfjJrsgBcvHoSm3jJ1qxd
S+ZCsjM=
-----END CERTIFICATE-----
`
	opensslCAKeyPEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgrX7evAG4c3h9k1SA
7dZC2jCcU0UOXTaXZF7YiSIeQLyhRANCAAScyI2p8jglSCcGOOgfIl0fF282lY/Q
NZ9twYC8FDtjVqwh12vjFKMzve+cYWvvgkT3r8C8a6aN0U0Ov7qyQMDR
-----END PRIVATE KEY-----
`
	// openssl x509 -in ca.pem -noout -ext subjectKeyIdentifier
	opensslCASKI = "82442f32b60e849de4d2064b621633ae954c35c7"
	// openssl x509 -in ca.pem -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum
	opensslCAKeyID = "8787a0128436c18ccf278f6618b566faed694f0884473bc8217f98f7748d3b04"
)
