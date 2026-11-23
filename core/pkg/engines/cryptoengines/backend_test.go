package cryptoengines

import (
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/kmip"
	"github.com/stretchr/testify/assert"
)

func TestCapabilitiesSupports(t *testing.T) {
	caps := Capabilities{Items: []Capability{{Operation: kmip.OpSign, Algorithm: kmip.RSA, Lengths: []int{2048, 3072}}}}

	assert.True(t, caps.Supports(kmip.OpSign, kmip.RSA, 2048))
	assert.True(t, caps.Supports(kmip.OpSign, kmip.RSA, 3072))
	assert.False(t, caps.Supports(kmip.OpSign, kmip.RSA, 4096), "length not listed")
	assert.False(t, caps.Supports(kmip.OpSign, kmip.ECDSA, 256), "algorithm not listed")
	assert.False(t, caps.Supports(kmip.OpCreateKeyPair, kmip.RSA, 2048), "operation not listed")
	assert.False(t, Capabilities{}.Supports(kmip.OpSign, kmip.RSA, 2048), "no capabilities")
}
