package kmip

import "fmt"

// ObjectType is the KMIP Object Type enumeration (§11.35).
type ObjectType uint32

const (
	SymmetricKey ObjectType = 0x02
	PublicKey    ObjectType = 0x03
	PrivateKey   ObjectType = 0x04
)

var objectTypeNames = map[ObjectType]string{
	SymmetricKey: "SymmetricKey",
	PublicKey:    "PublicKey",
	PrivateKey:   "PrivateKey",
}

// String returns the KMIP CamelCase name, or the hex value when it is not a known one.
func (v ObjectType) String() string { return name(objectTypeNames, v) }

// ParseObjectType parses a KMIP CamelCase name.
func ParseObjectType(s string) (ObjectType, error) { return parse(objectTypeNames, s, "object type") }

// CryptographicAlgorithm is the KMIP Cryptographic Algorithm enumeration (§11.12).
type CryptographicAlgorithm uint32

const (
	AES   CryptographicAlgorithm = 0x03
	RSA   CryptographicAlgorithm = 0x04
	ECDSA CryptographicAlgorithm = 0x06
)

var algorithmNames = map[CryptographicAlgorithm]string{
	AES:   "AES",
	RSA:   "RSA",
	ECDSA: "ECDSA",
}

// String returns the KMIP CamelCase name, or the hex value when it is not a known one.
func (v CryptographicAlgorithm) String() string { return name(algorithmNames, v) }

// ParseCryptographicAlgorithm parses a KMIP CamelCase name.
func ParseCryptographicAlgorithm(s string) (CryptographicAlgorithm, error) {
	return parse(algorithmNames, s, "cryptographic algorithm")
}

// Operation is the KMIP Operation enumeration (§11.37).
type Operation uint32

const (
	OpCreate          Operation = 0x01
	OpCreateKeyPair   Operation = 0x02
	OpRegister        Operation = 0x03
	OpDestroy         Operation = 0x14
	OpSign            Operation = 0x21
	OpSignatureVerify Operation = 0x22
)

var operationNames = map[Operation]string{
	OpCreate:          "Create",
	OpCreateKeyPair:   "CreateKeyPair",
	OpRegister:        "Register",
	OpDestroy:         "Destroy",
	OpSign:            "Sign",
	OpSignatureVerify: "SignatureVerify",
}

// String returns the KMIP CamelCase name, or the hex value when it is not a known one.
func (v Operation) String() string { return name(operationNames, v) }

// ParseOperation parses a KMIP CamelCase name.
func ParseOperation(s string) (Operation, error) { return parse(operationNames, s, "operation") }

func name[T ~uint32](names map[T]string, v T) string {
	if n, ok := names[v]; ok {
		return n
	}
	return fmt.Sprintf("0x%08x", uint32(v))
}

func parse[T ~uint32](names map[T]string, s, kind string) (T, error) {
	for v, n := range names {
		if n == s {
			return v, nil
		}
	}
	return 0, fmt.Errorf("unknown KMIP %s %q", kind, s)
}
