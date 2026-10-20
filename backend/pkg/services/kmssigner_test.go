package services

import (
	"context"
	"crypto"
	"crypto/rand"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signingKMS records the identifier each signature is requested for; any other call fails the test.
type signingKMS struct {
	services.KMSService
	identifiers []string
}

func (k *signingKMS) SignMessage(_ context.Context, input services.SignMessageInput) (*models.MessageSignature, error) {
	k.identifiers = append(k.identifiers, input.Identifier)
	return &models.MessageSignature{Signature: []byte("signature")}, nil
}

// The same key can be held by several engines, so the signer addresses it with its engine.
func TestKMSSignerAddressesTheKeyWithItsEngine(t *testing.T) {
	digest := make([]byte, 32)
	_, err := rand.Read(digest)
	require.NoError(t, err)

	for name, test := range map[string]struct {
		key      models.Key
		expected string
	}{
		"PKCS11URI":        {models.Key{KeyID: "key-1", EngineID: "engine-2", PKCS11URI: "pkcs11:token-id=engine-2;id=key-1;type=private"}, "pkcs11:token-id=engine-2;id=key-1;type=private"},
		"EngineWithoutURI": {models.Key{KeyID: "key-1", EngineID: "engine-2"}, "pkcs11:token-id=engine-2;id=key-1;type=private"},
		"KeyIDOnly":        {models.Key{KeyID: "key-1"}, "key-1"},
	} {
		t.Run(name, func(t *testing.T) {
			kms := &signingKMS{}
			test.key.Algorithm = "RSA"

			_, err := NewKMSCryptoSigner(context.Background(), test.key, kms).Sign(rand.Reader, digest, crypto.SHA256)

			require.NoError(t, err)
			assert.Equal(t, []string{test.expected}, kms.identifiers)
		})
	}
}
