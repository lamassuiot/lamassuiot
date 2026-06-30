package controllers

import (
	"encoding/asn1"
	"testing"
)

// buildCertStatusTLV encodes a CertStatus ::= SEQUENCE {
//
//	certHash   OCTET STRING,
//	certReqId  INTEGER,
//	statusInfo PKIStatusInfo OPTIONAL }
//
// statusInfoDER, when non-nil, is appended verbatim as the optional statusInfo.
func buildCertStatusTLV(t *testing.T, certHash []byte, certReqID int, statusInfoDER []byte) []byte {
	t.Helper()
	hashDER, err := asn1.Marshal(certHash) // OCTET STRING
	if err != nil {
		t.Fatalf("marshal certHash: %v", err)
	}
	reqIDDER, err := asn1.Marshal(certReqID) // INTEGER
	if err != nil {
		t.Fatalf("marshal certReqId: %v", err)
	}
	content := append([]byte{}, hashDER...)
	content = append(content, reqIDDER...)
	content = append(content, statusInfoDER...)
	seqDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      content,
	})
	if err != nil {
		t.Fatalf("marshal CertStatus SEQUENCE: %v", err)
	}
	return seqDER
}

// buildCertConfirmContent encodes CertConfirmContent ::= SEQUENCE OF CertStatus.
// This is exactly what body.Bytes carries for a certConf body, because the
// PKIBody CHOICE uses EXPLICIT tagging: certConf [24] EXPLICIT CertConfirmContent
// → the [24] element's content is the full CertConfirmContent SEQUENCE.
func buildCertConfirmContent(t *testing.T, certStatusTLVs ...[]byte) []byte {
	t.Helper()
	var content []byte
	for _, cs := range certStatusTLVs {
		content = append(content, cs...)
	}
	seqDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      content,
	})
	if err != nil {
		t.Fatalf("marshal CertConfirmContent SEQUENCE: %v", err)
	}
	return seqDER
}

// TestDecodeCertConfStatuses_MultiStatus verifies the decoder reports all
// CertStatus entries when the EE sends more than one (RFC 9483 §4.1.1 only
// permits one in this profile, so handleCertConf must be able to see >1).
func TestDecodeCertConfStatuses_MultiStatus(t *testing.T) {
	hash := make([]byte, 32)
	cs := buildCertStatusTLV(t, hash, 0, nil)

	body := buildCertConfirmContent(t, cs, cs, cs)
	statuses, err := decodeCertConfStatuses(body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(statuses) != 3 {
		t.Fatalf("expected 3 statuses, got %d", len(statuses))
	}
}

// TestDecodeCertConfStatuses_NegativeCertReqID verifies certReqId=-1 is decoded
// as -1 (so the structural check can reject it).
func TestDecodeCertConfStatuses_NegativeCertReqID(t *testing.T) {
	hash := make([]byte, 32)
	cs := buildCertStatusTLV(t, hash, -1, nil)
	body := buildCertConfirmContent(t, cs)
	statuses, err := decodeCertConfStatuses(body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(statuses) != 1 {
		t.Fatalf("expected 1 status, got %d", len(statuses))
	}
	if statuses[0].CertReqID != -1 {
		t.Fatalf("expected certReqId -1, got %d", statuses[0].CertReqID)
	}
}

// TestDecodeCertConfStatuses_AcceptedWithFailInfo verifies a statusInfo with
// status=accepted(0) AND a failInfo bit is decoded so the structural check can
// reject the inconsistency.
func TestDecodeCertConfStatuses_AcceptedWithFailInfo(t *testing.T) {
	hash := make([]byte, 32)

	// PKIStatusInfo ::= SEQUENCE { status INTEGER(0), failInfo BIT STRING }
	// badRequest is bit 2.
	statusDER, err := asn1.Marshal(0)
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	failInfo := asn1.BitString{Bytes: []byte{0x20}, BitLength: 3} // bit 2 set
	failDER, err := asn1.Marshal(failInfo)
	if err != nil {
		t.Fatalf("marshal failInfo: %v", err)
	}
	siContent := append(append([]byte{}, statusDER...), failDER...)
	siDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      siContent,
	})
	if err != nil {
		t.Fatalf("marshal statusInfo: %v", err)
	}

	cs := buildCertStatusTLV(t, hash, 0, siDER)
	body := buildCertConfirmContent(t, cs)
	statuses, err := decodeCertConfStatuses(body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(statuses) != 1 {
		t.Fatalf("expected 1 status, got %d", len(statuses))
	}
	if statuses[0].StatusInfo.Status != PKIStatus(pkiStatusAccepted) {
		t.Fatalf("expected status accepted, got %d", statuses[0].StatusInfo.Status)
	}
	if statuses[0].StatusInfo.FailInfo.BitLength == 0 {
		t.Fatalf("expected non-empty failInfo, got empty")
	}
}

// TestDecodeCertConfStatuses_SingleAccepted verifies the happy-path: a single
// CertStatus with certReqId 0 and no statusInfo decodes to exactly one entry
// with the correct certHash.
func TestDecodeCertConfStatuses_SingleAccepted(t *testing.T) {
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i)
	}
	cs := buildCertStatusTLV(t, hash, 0, nil)
	body := buildCertConfirmContent(t, cs)
	statuses, err := decodeCertConfStatuses(body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(statuses) != 1 {
		t.Fatalf("expected 1 status, got %d", len(statuses))
	}
	if statuses[0].CertReqID != 0 {
		t.Fatalf("expected certReqId 0, got %d", statuses[0].CertReqID)
	}
	if len(statuses[0].CertHash) != 32 {
		t.Fatalf("expected 32-byte certHash, got %d", len(statuses[0].CertHash))
	}
	if statuses[0].CertHash[5] != 5 {
		t.Fatalf("certHash content mismatch: got %x", statuses[0].CertHash)
	}
}

// TestDecodeCertConfStatuses_ExplicitHashAlg verifies the optional hashAlg [0]
// field is parsed when EXPLICIT-tagged (the CMP module uses EXPLICIT TAGS), so
// [0] wraps a full AlgorithmIdentifier SEQUENCE. Without unwrapping the
// SEQUENCE the OID would be lost and the server would recompute certHash with
// the default algorithm, wrongly rejecting a valid pvno=3 different-hash
// confirmation (RFC 9483 §4.1.1 / RFC 9810 §5.3.18).
func TestDecodeCertConfStatuses_ExplicitHashAlg(t *testing.T) {
	hash := make([]byte, 64)

	// AlgorithmIdentifier { algorithm = id-sha512 (2.16.840.1.101.3.4.2.3) }
	sha512OID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	algIDDER, err := asn1.Marshal(struct {
		Algorithm asn1.ObjectIdentifier
	}{Algorithm: sha512OID})
	if err != nil {
		t.Fatalf("marshal AlgorithmIdentifier: %v", err)
	}
	// hashAlg [0] EXPLICIT AlgorithmIdentifier — the [0] content is the whole
	// AlgorithmIdentifier SEQUENCE TLV.
	hashAlgField, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      algIDDER,
	})
	if err != nil {
		t.Fatalf("marshal hashAlg [0]: %v", err)
	}

	// CertStatus { certHash, certReqId=0, hashAlg [0] } (no statusInfo).
	hashDER, _ := asn1.Marshal(hash)
	reqIDDER, _ := asn1.Marshal(0)
	content := append(append(append([]byte{}, hashDER...), reqIDDER...), hashAlgField...)
	cs, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      content,
	})
	if err != nil {
		t.Fatalf("marshal CertStatus: %v", err)
	}

	body := buildCertConfirmContent(t, cs)
	statuses, err := decodeCertConfStatuses(body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(statuses) != 1 {
		t.Fatalf("expected 1 status, got %d", len(statuses))
	}
	if !statuses[0].HashAlgOID.Equal(sha512OID) {
		t.Fatalf("expected hashAlg OID %v, got %v", sha512OID, statuses[0].HashAlgOID)
	}
}
