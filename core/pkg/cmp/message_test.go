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

// TestHeaderRoundTripsRecipKIDAndFreeText is a regression test for silent field
// loss in PKIHeader decoding.
//
// Go's struct-based ASN.1 decoder matches SEQUENCE elements positionally. When
// Header declared no recipKID [3] / freeText [7] fields, a peer that sent either
// one caused the decoder's walk to stop there, and EVERY later OPTIONAL field —
// transactionID, senderNonce, recipNonce, generalInfo — silently decoded as its
// zero value while Unmarshal still reported success. A CMP server that lost the
// transactionID and nonces without any error is unable to correlate the
// transaction or enforce replay protection, so this failed open and quietly.
func TestHeaderRoundTripsRecipKIDAndFreeText(t *testing.T) {
	sender, err := cmp.GeneralNameDirectoryName(pkix.Name{CommonName: "client"})
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := cmp.GeneralNameDirectoryName(pkix.Name{CommonName: "ca"})
	if err != nil {
		t.Fatal(err)
	}

	freeTextDER, err := asn1.MarshalWithParams("some diagnostic text", "utf8")
	if err != nil {
		t.Fatal(err)
	}

	txID := []byte("0123456789abcdef")
	senderNonce := []byte("fedcba9876543210")
	recipNonce := []byte("00112233445566778")

	original := cmp.Header{
		PVNO:      2,
		Sender:    sender,
		Recipient: recipient,
		// recipKID [3] and freeText [7] both sit BETWEEN the fields below, so
		// their presence is exactly what used to break the positional walk.
		SenderKID:     []byte("sender-key-id"),
		RecipKID:      []byte("recipient-key-id"),
		TransactionID: txID,
		SenderNonce:   senderNonce,
		RecipNonce:    recipNonce,
		FreeText:      cmp.PKIFreeText{{FullBytes: freeTextDER}},
		GeneralInfo: []cmp.InfoTypeAndValue{{
			InfoType: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 13},
		}},
	}

	headerDER, err := asn1.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}

	var decoded cmp.Header
	rest, err := asn1.Unmarshal(headerDER, &decoded)
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("%d trailing bytes after header", len(rest))
	}

	// The fields positioned after recipKID [3] and freeText [7] are the ones that
	// used to be silently zeroed.
	if string(decoded.TransactionID) != string(txID) {
		t.Errorf("transactionID lost: got %q want %q", decoded.TransactionID, txID)
	}
	if string(decoded.SenderNonce) != string(senderNonce) {
		t.Errorf("senderNonce lost: got %q want %q", decoded.SenderNonce, senderNonce)
	}
	if string(decoded.RecipNonce) != string(recipNonce) {
		t.Errorf("recipNonce lost: got %q want %q", decoded.RecipNonce, recipNonce)
	}
	if len(decoded.GeneralInfo) != 1 {
		t.Errorf("generalInfo lost: got %d entries want 1", len(decoded.GeneralInfo))
	}

	// And the two newly-modelled fields must themselves survive the round trip.
	if string(decoded.RecipKID) != string(original.RecipKID) {
		t.Errorf("recipKID lost: got %q want %q", decoded.RecipKID, original.RecipKID)
	}
	if len(decoded.FreeText) != 1 {
		t.Fatalf("freeText lost: got %d entries want 1", len(decoded.FreeText))
	}
	var gotText string
	if _, err := asn1.Unmarshal(decoded.FreeText[0].FullBytes, &gotText); err != nil {
		t.Fatalf("decode freeText entry: %v", err)
	}
	if gotText != "some diagnostic text" {
		t.Errorf("freeText content: got %q", gotText)
	}
}

// TestHeaderDecodePreservesFieldsAfterRecipKID is the true regression test for
// the positional-decode field loss: it builds the PKIHeader DER BY HAND with a
// recipKID [3] present, so it compiles regardless of whether Header declares
// that field, and then asserts the fields positioned after it survive.
//
// With recipKID unmodelled, the decoder's positional walk stopped at tag 3 and
// transactionID/senderNonce/recipNonce/generalInfo all came back as zero values
// with err == nil — a wire-format peer could silently strip a CMP server's
// transaction correlation and replay protection.
func TestHeaderDecodePreservesFieldsAfterRecipKID(t *testing.T) {
	sender, err := cmp.GeneralNameDirectoryName(pkix.Name{CommonName: "client"})
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := cmp.GeneralNameDirectoryName(pkix.Name{CommonName: "ca"})
	if err != nil {
		t.Fatal(err)
	}

	ctxField := func(tag int, inner []byte) []byte {
		der, mErr := asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        tag,
			IsCompound: true,
			Bytes:      inner,
		})
		if mErr != nil {
			t.Fatal(mErr)
		}
		return der
	}
	octet := func(b []byte) []byte {
		der, mErr := asn1.Marshal(b)
		if mErr != nil {
			t.Fatal(mErr)
		}
		return der
	}

	pvno, err := asn1.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}

	txID := []byte("0123456789abcdef")
	senderNonce := []byte("fedcba9876543210")

	var content []byte
	content = append(content, pvno...)
	content = append(content, sender.FullBytes...)
	content = append(content, recipient.FullBytes...)
	content = append(content, ctxField(3, octet([]byte("recipient-key-id")))...) // recipKID [3]
	content = append(content, ctxField(4, octet(txID))...)                       // transactionID [4]
	content = append(content, ctxField(5, octet(senderNonce))...)                // senderNonce [5]

	headerDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      content,
	})
	if err != nil {
		t.Fatal(err)
	}

	var decoded cmp.Header
	if _, err := asn1.Unmarshal(headerDER, &decoded); err != nil {
		t.Fatalf("decode hand-built header: %v", err)
	}

	if string(decoded.TransactionID) != string(txID) {
		t.Errorf("transactionID after recipKID lost: got %q want %q", decoded.TransactionID, txID)
	}
	if string(decoded.SenderNonce) != string(senderNonce) {
		t.Errorf("senderNonce after recipKID lost: got %q want %q", decoded.SenderNonce, senderNonce)
	}
}
