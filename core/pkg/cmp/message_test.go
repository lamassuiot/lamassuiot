package cmp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	cmp "github.com/lamassuiot/lamassuiot/core/v3/pkg/cmp"
)

func TestExternalClientCanMarshalUnprotectedMessage(t *testing.T) {
	sender, err := cmp.GeneralNameDirectoryName(pkix.Name{CommonName: "client"})
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := cmp.GeneralNameDirectoryName(pkix.Name{CommonName: "ca"})
	if err != nil {
		t.Fatal(err)
	}
	bodyDER, err := asn1.Marshal(asn1.NullRawValue)
	if err != nil {
		t.Fatal(err)
	}
	messageDER, err := cmp.MarshalUnprotectedMessage(cmp.Header{
		PVNO:          cmp.PVNOCMP2000,
		Sender:        sender,
		Recipient:     recipient,
		TransactionID: []byte("transaction-id"),
		SenderNonce:   []byte("0123456789abcdef"),
	}, cmp.BodyTagPKIConf, bodyDER)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := cmp.ParseRawMessage(messageDER)
	if err != nil {
		t.Fatal(err)
	}
	if raw.Body.Tag != cmp.BodyTagPKIConf {
		t.Fatalf("body tag = %d, want %d", raw.Body.Tag, cmp.BodyTagPKIConf)
	}
}

func TestExternalClientCanMarshalAndVerifyProtectedMessage(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "client"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		SubjectKeyId: []byte{1, 2, 3, 4},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := cmp.GeneralNameDirectoryName(pkix.Name{CommonName: "ca"})
	if err != nil {
		t.Fatal(err)
	}
	bodyDER, err := asn1.Marshal(asn1.NullRawValue)
	if err != nil {
		t.Fatal(err)
	}
	messageDER, err := cmp.MarshalProtectedMessage(cmp.Header{
		PVNO:          cmp.PVNOCMP2000,
		Recipient:     recipient,
		TransactionID: []byte("transaction-id"),
		SenderNonce:   []byte("0123456789abcdef"),
	}, cmp.BodyTagPKIConf, bodyDER, []*x509.Certificate{cert}, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := cmp.ParseRawMessage(messageDER)
	if err != nil {
		t.Fatal(err)
	}
	var header cmp.Header
	if _, err := asn1.Unmarshal(raw.Header.FullBytes, &header); err != nil {
		t.Fatal(err)
	}
	verified, err := cmp.VerifyMessageProtection(raw, header.ProtectionAlg, true)
	if err != nil {
		t.Fatal(err)
	}
	if !verified.Equal(cert) {
		t.Fatal("verified protection certificate differs from signer certificate")
	}
}
