package registry_test

import (
	"testing"

	cryptoenginesv2 "github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines_v2"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines_v2/registry"
)

func TestValidateAlgorithm(t *testing.T) {
	r := registry.NewBuiltinRegistry()

	cases := []struct {
		name    string
		spec    cryptoenginesv2.KeySpec
		op      cryptoenginesv2.Operation
		alg     cryptoenginesv2.AlgorithmID
		wantErr bool
	}{
		{"rsa pss ok", cryptoenginesv2.KeySpecRSA2048, cryptoenginesv2.OpSign, cryptoenginesv2.AlgRSASSAPSSSHA256, false},
		{"rsa pkcs1 ok", cryptoenginesv2.KeySpecRSA4096, cryptoenginesv2.OpSign, cryptoenginesv2.AlgRSASSAPKCS1V15SHA512, false},
		{"rsa oaep verify-side ok", cryptoenginesv2.KeySpecRSA3072, cryptoenginesv2.OpDecrypt, cryptoenginesv2.AlgRSAESOAEPSHA256, false},
		{"ecdsa on rsa rejected", cryptoenginesv2.KeySpecRSA2048, cryptoenginesv2.OpSign, cryptoenginesv2.AlgECDSASHA256, true},
		{"ecdsa 256 not valid on p384", cryptoenginesv2.KeySpecECCNISTP384, cryptoenginesv2.OpSign, cryptoenginesv2.AlgECDSASHA256, true},
		{"ecdsa 384 ok on p384", cryptoenginesv2.KeySpecECCNISTP384, cryptoenginesv2.OpSign, cryptoenginesv2.AlgECDSASHA384, false},
		{"ecdh ok on ec key", cryptoenginesv2.KeySpecECCNISTP256, cryptoenginesv2.OpAgreeKey, cryptoenginesv2.AlgECDH, false},
		{"sign op on oaep alg rejected", cryptoenginesv2.KeySpecRSA2048, cryptoenginesv2.OpSign, cryptoenginesv2.AlgRSAESOAEPSHA256, true},
		{"unknown alg rejected", cryptoenginesv2.KeySpecRSA2048, cryptoenginesv2.OpSign, cryptoenginesv2.AlgorithmID("NOPE"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := r.ValidateAlgorithm(tc.spec, tc.op, tc.alg)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestAlgorithmsFor_RSAKeySpecServesManySigningAlgorithms(t *testing.T) {
	r := registry.NewBuiltinRegistry()
	got := r.AlgorithmsFor(cryptoenginesv2.KeySpecRSA2048, cryptoenginesv2.OpSign)
	// One RSA_2048 key must serve all six RSASSA signing algorithms.
	if len(got) != 6 {
		t.Fatalf("expected 6 signing algorithms for RSA_2048, got %d: %v", len(got), got)
	}
}

func TestGetKeySpec_UnknownRejected(t *testing.T) {
	r := registry.NewBuiltinRegistry()
	if _, err := r.GetKeySpec(cryptoenginesv2.KeySpec("BOGUS")); err == nil {
		t.Fatalf("expected error for unknown key spec")
	}
}
