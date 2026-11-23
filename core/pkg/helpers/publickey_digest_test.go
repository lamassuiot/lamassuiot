package helpers_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/engines/crypto/software"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// Every crypto engine names a key with the digest of its public key, so the name can be computed from the
// public key alone, without an engine.
func TestPublicKeyDigestMatchesTheSoftwareEngine(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	engine := software.NewSoftwareCryptoEngine(logrus.NewEntry(logrus.New()))

	for name, pub := range map[string]any{"RSA": &rsaKey.PublicKey, "ECDSA": &ecKey.PublicKey} {
		t.Run(name, func(t *testing.T) {
			want, err := engine.EncodePKIXPublicKeyDigest(context.Background(), pub)
			require.NoError(t, err)

			got, err := helpers.PublicKeyDigest(pub)
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}

	t.Run("an unsupported key is an error", func(t *testing.T) {
		_, err := helpers.PublicKeyDigest("not a public key")
		require.Error(t, err)
	})
}
