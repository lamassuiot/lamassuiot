package models

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCompositeKeyTypes(t *testing.T) {
	tests := []struct {
		name string
		want x509.PublicKeyAlgorithm
	}{
		{"Composite-ML-DSA-RSA", x509.CompositeMLDSARSA},
		{"Composite-ML-DSA-ECDSA", x509.CompositeMLDSAECDSA},
		{"Composite-ML-DSA-Ed25519", x509.CompositeMLDSAEd25519},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseKeyType(tt.name)
			require.NoError(t, err)
			assert.Equal(t, KeyType(tt.want), *got)
			assert.Equal(t, tt.name, got.String())
		})
	}
}
