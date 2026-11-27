package kmip

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The values are KMIP's (Specification §11), identical in 2.1 and 3.0: a TTLV or JSON encoder relies on them.
func TestEnumValues(t *testing.T) {
	assert.EqualValues(t, 0x02, SymmetricKey)
	assert.EqualValues(t, 0x03, PublicKey)
	assert.EqualValues(t, 0x04, PrivateKey)

	assert.EqualValues(t, 0x03, AES)
	assert.EqualValues(t, 0x04, RSA)
	assert.EqualValues(t, 0x06, ECDSA)

	assert.EqualValues(t, 0x01, OpCreate)
	assert.EqualValues(t, 0x02, OpCreateKeyPair)
	assert.EqualValues(t, 0x03, OpRegister)
	assert.EqualValues(t, 0x14, OpDestroy)
	assert.EqualValues(t, 0x21, OpSign)
	assert.EqualValues(t, 0x22, OpSignatureVerify)
}

func TestEnumNamesRoundTrip(t *testing.T) {
	objectTypes := map[ObjectType]string{SymmetricKey: "SymmetricKey", PublicKey: "PublicKey", PrivateKey: "PrivateKey"}
	for v, name := range objectTypes {
		assert.Equal(t, name, v.String())
		parsed, err := ParseObjectType(name)
		require.NoError(t, err)
		assert.Equal(t, v, parsed)
	}

	algorithms := map[CryptographicAlgorithm]string{AES: "AES", RSA: "RSA", ECDSA: "ECDSA"}
	for v, name := range algorithms {
		assert.Equal(t, name, v.String())
		parsed, err := ParseCryptographicAlgorithm(name)
		require.NoError(t, err)
		assert.Equal(t, v, parsed)
	}

	operations := map[Operation]string{
		OpCreate: "Create", OpCreateKeyPair: "CreateKeyPair", OpRegister: "Register",
		OpDestroy: "Destroy", OpSign: "Sign", OpSignatureVerify: "SignatureVerify",
	}
	for v, name := range operations {
		assert.Equal(t, name, v.String())
		parsed, err := ParseOperation(name)
		require.NoError(t, err)
		assert.Equal(t, v, parsed)
	}
}

func TestEnumUnknownValues(t *testing.T) {
	_, err := ParseObjectType("Nope")
	assert.Error(t, err)
	_, err = ParseCryptographicAlgorithm("Nope")
	assert.Error(t, err)
	_, err = ParseOperation("Nope")
	assert.Error(t, err)

	assert.Equal(t, "0x000000ff", ObjectType(0xff).String())
	assert.Equal(t, "0x000000ff", CryptographicAlgorithm(0xff).String())
	assert.Equal(t, "0x000000ff", Operation(0xff).String())
}
