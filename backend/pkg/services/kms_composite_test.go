package services

import (
	"context"
	"crypto"
	"crypto/x509"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	coreservices "github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	servicemock "github.com/lamassuiot/lamassuiot/core/v3/pkg/services/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestCompositeAlgorithmMetadata(t *testing.T) {
	tests := []struct {
		firstVariant int
		lastVariant  int
		keyType      string
	}{
		{1, 8, x509.CompositeMLDSARSA.String()},
		{9, 13, x509.CompositeMLDSAECDSA.String()},
		{14, 15, x509.CompositeMLDSAEd25519.String()},
	}

	for _, tt := range tests {
		for variant := tt.firstVariant; variant <= tt.lastVariant; variant++ {
			algorithm := x509.CompositeAlgorithms[variant-1]
			gotType, ok := compositeKeyType(algorithm)
			require.True(t, ok)
			assert.Equal(t, tt.keyType, gotType)

			gotVariant, ok := compositeVariant(algorithm)
			require.True(t, ok)
			assert.Equal(t, variant, gotVariant)
		}
	}
}

func TestParseCompositeSignatureAlgorithms(t *testing.T) {
	for _, algorithm := range []string{
		"COMPOSITE_MLDSA_RSA_PURE",
		"COMPOSITE_MLDSA_ECDSA_PURE",
		"COMPOSITE_MLDSA_ED25519_PURE",
	} {
		hash, isRSA, isPSS, err := parseAlgorithm(algorithm)
		require.NoError(t, err)
		assert.Zero(t, hash)
		assert.False(t, isRSA)
		assert.False(t, isPSS)
	}
}

func TestKMSCryptoSignerSelectsCompositeSignatureAlgorithm(t *testing.T) {
	tests := []struct {
		keyType   string
		signature string
	}{
		{x509.CompositeMLDSARSA.String(), "COMPOSITE_MLDSA_RSA_PURE"},
		{x509.CompositeMLDSAECDSA.String(), "COMPOSITE_MLDSA_ECDSA_PURE"},
		{x509.CompositeMLDSAEd25519.String(), "COMPOSITE_MLDSA_ED25519_PURE"},
	}

	for _, tt := range tests {
		t.Run(tt.keyType, func(t *testing.T) {
			ctx := context.Background()
			sdk := new(servicemock.MockKMSService)
			sdk.On("SignMessage", ctx, mock.MatchedBy(func(input coreservices.SignMessageInput) bool {
				return input.Algorithm == tt.signature && input.MessageType == models.Hashed
			})).Return(&models.MessageSignature{Signature: []byte("signature")}, nil).Once()

			signer := NewKMSCryptoSigner(ctx, models.Key{KeyID: "key-id", Algorithm: tt.keyType}, sdk)
			signature, err := signer.Sign(nil, []byte("message"), crypto.Hash(0))
			require.NoError(t, err)
			assert.Equal(t, []byte("signature"), signature)
			sdk.AssertExpectations(t)
		})
	}
}
