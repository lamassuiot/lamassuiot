package cmp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"

	cmp "github.com/lamassuiot/lamassuiot/core/v3/pkg/cmp"
)

func ExampleBuildEnrollmentRequest() {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sender, _ := cmp.GeneralNameDirectoryName(pkix.Name{CommonName: "device-1"})
	recipient, _ := cmp.GeneralNameDirectoryName(pkix.Name{CommonName: "enrollment-ca"})
	header, _ := cmp.NewHeader(cmp.HeaderOptions{Sender: sender, Recipient: recipient})
	body, _ := cmp.BuildEnrollmentRequest(cmp.BodyIR, cmp.EnrollmentRequestOptions{
		Subject:   pkix.Name{CommonName: "device-1"},
		PublicKey: &key.PublicKey,
		Proof:     cmp.ProofOfPossessionSignature,
		Signer:    key,
	})
	_, _ = cmp.MarshalUnprotected(header, body)
}

func ExampleBuildKGAEnrollmentRequest() {
	body, _ := cmp.BuildKGAEnrollmentRequest(cmp.BodyIR, cmp.KGAEnrollmentRequestOptions{
		Subject:      pkix.Name{CommonName: "device-with-server-generated-key"},
		KeyAlgorithm: x509.RSA,
	})
	_ = body
}
