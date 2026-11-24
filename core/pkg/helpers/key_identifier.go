package helpers

import "regexp"

var (
	keyUUIDShape   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	keyDigestShape = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
)

// IsKeyUUID reports whether s has the canonical form of a UUID (8-4-4-4-12 hexadecimal digits), which is
// how the id of a KMS key is written.
func IsKeyUUID(s string) bool {
	return keyUUIDShape.MatchString(s)
}

// IsKeyDigest reports whether s has the shape of the digest of a public key: the 64 hexadecimal digits of a
// SHA-256 (see PublicKeyDigest).
func IsKeyDigest(s string) bool {
	return keyDigestShape.MatchString(s)
}
