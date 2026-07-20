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

	cmp "github.com/lamassuiot/lamassuiot/core/v3/pkg/cmp"
)

func TestClientBodyBuildersRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := cmp.BuildEnrollmentRequest(cmp.BodyIR, cmp.EnrollmentRequestOptions{
		Subject:    pkix.Name{CommonName: "device-1"},
		PublicKey:  &key.PublicKey,
		Proof:      cmp.ProofOfPossessionSignature,
		Signer:     key,
		RegToken:   "one-time-token",
		Extensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: []byte{0x30, 0x00}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := cmp.DecodeFirstCertReq(enrollment.DER)
	if err != nil {
		t.Fatal(err)
	}
	if request.CertReqID != 0 || request.POPORaw.Tag != 1 || request.RegToken != "one-time-token" {
		t.Fatalf("unexpected decoded enrollment request: %+v", request)
	}

	reason := 1
	revocation, err := cmp.BuildRevocationRequest(cmp.RevocationRequestOptions{SerialNumber: big.NewInt(42), Reason: &reason})
	if err != nil {
		t.Fatal(err)
	}
	revDetails, err := cmp.DecodeRevDetails(revocation.DER)
	if err != nil {
		t.Fatal(err)
	}
	if new(big.Int).SetBytes(revDetails.SerialNumber).Cmp(big.NewInt(42)) != 0 || len(revDetails.Reasons) != 1 || revDetails.Reasons[0] != reason {
		t.Fatalf("unexpected decoded revocation request: %+v", revDetails)
	}

	poll, err := cmp.BuildPollReq(7)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := cmp.DecodePollReqContent(poll.DER); err != nil || id != 7 {
		t.Fatalf("decoded poll request = %d, %v", id, err)
	}

	general, err := cmp.BuildGenMsg(cmp.InfoTypeAndValue{InfoType: cmp.OIDImplicitConfirm(), InfoValue: asn1.NullRawValue})
	if err != nil || general.Type != cmp.BodyGenMsg {
		t.Fatalf("general message = %+v, %v", general, err)
	}
	values, err := cmp.DecodeGenMsg(general)
	if err != nil || len(values) != 1 || !values[0].InfoType.Equal(cmp.OIDImplicitConfirm()) {
		t.Fatalf("decoded general message = %+v, %v", values, err)
	}
}

func TestClientBuildsP10CRCertConfAndNestedMessages(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "device-p10"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	p10cr, err := cmp.BuildP10CRRequest(csr)
	if err != nil || p10cr.Type != cmp.BodyP10CR {
		t.Fatalf("p10cr = %+v, %v", p10cr, err)
	}
	if _, err := cmp.DecodeP10CRRequest(p10cr); err != nil {
		t.Fatal(err)
	}

	cert, _ := testCertificate(t)
	confirmation, err := cmp.BuildCertConf(cmp.CertConfirmation{Certificate: cert, CertReqID: -1})
	if err != nil {
		t.Fatal(err)
	}
	statuses, err := cmp.DecodeCertConfStatuses(confirmation.DER)
	if err != nil || len(statuses) != 1 || statuses[0].CertReqID != -1 {
		t.Fatalf("decoded confirmations = %+v, %v", statuses, err)
	}

	sender, _ := cmp.GeneralNameDirectoryName(pkix.Name{CommonName: "device"})
	recipient, _ := cmp.GeneralNameDirectoryName(pkix.Name{CommonName: "ca"})
	header, err := cmp.NewHeader(cmp.HeaderOptions{Sender: sender, Recipient: recipient})
	if err != nil {
		t.Fatal(err)
	}
	messageDER, err := cmp.MarshalUnprotected(header, p10cr)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := cmp.ParseMessage(messageDER)
	if err != nil || parsed.Body.Type != cmp.BodyP10CR {
		t.Fatalf("parsed message = %+v, %v", parsed, err)
	}
	nested, err := cmp.BuildNested(messageDER)
	if err != nil || nested.Type != cmp.BodyNested {
		t.Fatalf("nested = %+v, %v", nested, err)
	}
	if nestedMessages, err := cmp.DecodeNested(nested); err != nil || len(nestedMessages) != 1 {
		t.Fatalf("decoded nested messages = %+v, %v", nestedMessages, err)
	}
}

func TestBuildKGAEnrollmentRequest(t *testing.T) {
	body, err := cmp.BuildKGAEnrollmentRequest(cmp.BodyIR, cmp.KGAEnrollmentRequestOptions{
		Subject:      pkix.Name{CommonName: "centrally-generated-device"},
		KeyAlgorithm: x509.RSA,
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := cmp.DecodeEnrollmentRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	if !request.ForKGA || request.KGAKeyAlgorithm != x509.RSA {
		t.Fatalf("decoded KGA request = %+v", request)
	}
	if len(request.POPORaw.FullBytes) != 0 {
		t.Fatal("KGA request unexpectedly contains proof of possession")
	}
	if _, err := cmp.BuildKGAEnrollmentRequest(cmp.BodyIR, cmp.KGAEnrollmentRequestOptions{KeyAlgorithm: x509.Ed25519}); err == nil {
		t.Fatal("expected unsupported KGA key algorithm error")
	}
}

func TestOIDAccessorsReturnIndependentValues(t *testing.T) {
	first := cmp.OIDImplicitConfirm()
	second := cmp.OIDImplicitConfirm()
	first[0] = 99
	if second[0] == 99 {
		t.Fatal("OID accessor exposed mutable package state")
	}
}

func TestParseErrorsCarryFailureInfo(t *testing.T) {
	_, err := cmp.ParseMessage([]byte{0x01, 0x01, 0x00})
	if err == nil {
		t.Fatal("expected malformed message error")
	}
	failure, ok := cmp.FailureInfoFromError(err)
	if !ok || failure != cmp.FailureBadDataFormat {
		t.Fatalf("failure info = %v, %v", failure, ok)
	}
}

func testCertificate(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "device"}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}
