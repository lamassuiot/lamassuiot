package controllers

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cmpPEMBlockType is the PEM block type used by standard CMP clients (RFC 6712 §3).
const cmpPEMBlockType = "CMP Request"

// samplesDir is the directory containing the reference CMP message files.
const samplesDir = "cmp_message_samples"

// --- PEM + rawPKIMessage parsing ---

// TestParsePEMEncodedCMPMessages is the primary table-driven test for the
// cmp_message_samples files. It validates:
//   - PEM block type
//   - ASN.1 unmarshal into rawPKIMessage
//   - PKIHeader PVNO
//   - PKIBody tag, ASN.1 class, and compound flag
//   - Subject CN extractable from the CertReqMessages body
func TestParsePEMEncodedCMPMessages(t *testing.T) {
	tests := []struct {
		name        string
		file        string
		wantBodyTag int    // expected PKIBody CHOICE tag (cmpBodyTag* constants)
		wantCN      string // expected Subject CommonName in the first CertTemplate
	}{
		{
			name:        "0001.ip - Initialization Request (ir, tag 0)",
			file:        "0001.ip",
			wantBodyTag: cmpBodyTagIR, // 0
			wantCN:      "0e59a0d7-3bdc-45e5-82d1-3855089289cb",
		},
		{
			name:        "0002.cr - Certificate Request (cr, tag 2)",
			file:        "0002.cr",
			wantBodyTag: cmpBodyTagCR, // 2
			wantCN:      "a04908c9-7b75-4bd5-96b4-ca26b6872a6d",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(samplesDir, tc.file))
			require.NoError(t, err, "reading sample file")

			// 1. PEM decode
			block, trailing := pem.Decode(data)
			require.NotNil(t, block, "expected a PEM block")
			assert.Equal(t, cmpPEMBlockType, block.Type, "PEM block type")
			assert.Empty(t, trailing, "no data expected after the PEM block")
			assert.NotEmpty(t, block.Bytes, "PEM payload (DER) must not be empty")

			// 2. DER → rawPKIMessage
			var msg rawPKIMessage
			leftover, err := asn1.Unmarshal(block.Bytes, &msg)
			require.NoError(t, err, "ASN.1 unmarshal into rawPKIMessage")
			// Extra bytes after PKIMessage are Protection + ExtraCerts (intentionally not
			// decoded by rawPKIMessage); do NOT assert leftover is empty.
			_ = leftover

			// 3. PKIHeader fields
			header, err := decodeRequestHeader(msg.Header.FullBytes)
			require.NoError(t, err, "decoding PKIHeader")
			assert.Equal(t, pvnoCMP2000, header.PVNO,
				"PVNO must be cmp2000 (2) per RFC 9480 §2.20")

			// 4. PKIBody tag and encoding
			assert.Equal(t, tc.wantBodyTag, msg.Body.Tag,
				"PKIBody CHOICE tag")
			assert.Equal(t, asn1.ClassContextSpecific, msg.Body.Class,
				"PKIBody must use context-specific class (IMPLICIT TAGS)")
			assert.True(t, msg.Body.IsCompound,
				"PKIBody must be compound/constructed (CertReqMessages is SEQUENCE)")
			assert.NotEmpty(t, msg.Body.Bytes,
				"PKIBody content must not be empty")

			// 5. Subject CN extractable
			cn, err := extractSubjectCNFromBody(msg.Body.Bytes)
			require.NoError(t, err, "extracting Subject CN from CertTemplate")
			assert.Equal(t, tc.wantCN, cn, "Subject CommonName")
		})
	}
}

// --- Body-tag semantics ---

// TestParseCMPBodyTagMeaning documents the mapping from file extension to the
// expected RFC 4210 PKIBody CHOICE tag.
func TestParseCMPBodyTagMeaning(t *testing.T) {
	tests := []struct {
		file    string
		tagName string
		wantTag int
	}{
		{"0001.ip", "ir (Initialization Request)", cmpBodyTagIR},
		{"0002.cr", "cr (Certificate Request)", cmpBodyTagCR},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s contains %s tag=%d", tc.file, tc.tagName, tc.wantTag), func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(samplesDir, tc.file))
			require.NoError(t, err)

			block, _ := pem.Decode(data)
			require.NotNil(t, block)

			var msg rawPKIMessage
			_, err = asn1.Unmarshal(block.Bytes, &msg)
			require.NoError(t, err)
			assert.Equal(t, tc.wantTag, msg.Body.Tag)
		})
	}
}

// --- Negative / error cases ---

// TestParseCMPPEM_Errors covers invalid inputs that must be rejected at the
// PEM-decode or ASN.1-unmarshal stage.
func TestParseCMPPEM_Errors(t *testing.T) {
	t.Run("empty input yields nil PEM block", func(t *testing.T) {
		block, _ := pem.Decode([]byte{})
		assert.Nil(t, block)
	})

	t.Run("plain text yields nil PEM block", func(t *testing.T) {
		block, _ := pem.Decode([]byte("not a pem encoded file"))
		assert.Nil(t, block)
	})

	t.Run("CERTIFICATE block type differs from CMP Request", func(t *testing.T) {
		pemData := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: []byte{0x30, 0x03, 0x02, 0x01, 0x01},
		})
		block, _ := pem.Decode(pemData)
		require.NotNil(t, block, "PEM itself is valid")
		assert.NotEqual(t, cmpPEMBlockType, block.Type,
			"CERTIFICATE block type must not equal CMP Request")
	})

	t.Run("all-zero DER inside CMP Request PEM fails ASN.1 unmarshal", func(t *testing.T) {
		pemData := pem.EncodeToMemory(&pem.Block{
			Type:  cmpPEMBlockType,
			Bytes: make([]byte, 16),
		})
		block, _ := pem.Decode(pemData)
		require.NotNil(t, block)

		var msg rawPKIMessage
		_, err := asn1.Unmarshal(block.Bytes, &msg)
		assert.Error(t, err, "all-zero bytes cannot form a valid PKIMessage")
	})

	t.Run("truncated DER inside CMP Request PEM fails ASN.1 unmarshal", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join(samplesDir, "0001.ip"))
		require.NoError(t, err)

		raw, _ := pem.Decode(data)
		require.NotNil(t, raw)

		// Keep only the outer SEQUENCE header (4 bytes) - body is missing.
		truncated := pem.EncodeToMemory(&pem.Block{
			Type:  cmpPEMBlockType,
			Bytes: raw.Bytes[:4],
		})
		block, _ := pem.Decode(truncated)
		require.NotNil(t, block)

		var msg rawPKIMessage
		_, err = asn1.Unmarshal(block.Bytes, &msg)
		assert.Error(t, err, "truncated DER must fail ASN.1 unmarshal")
	})

	t.Run("garbage body bytes fail CertReqMessages re-wrap", func(t *testing.T) {
		// rewrapBodyAsSequence must not panic; asn1.Unmarshal on garbage returns an error.
		garbage := []byte{0xFF, 0xFE, 0xFD, 0xFC}
		seq, err := rewrapBodyAsSequence(garbage)
		require.NoError(t, err, "rewrapBodyAsSequence itself never errors")

		var out []interface{}
		_, unmarshalErr := asn1.Unmarshal(seq, &out)
		// Garbage content should produce a structural error when interpreted as
		// a sequence of typed elements.
		assert.Error(t, unmarshalErr)
	})
}

// --- Internal helper unit tests ---

// TestCMPASN1Helpers exercises the low-level encoding helpers introduced in
// cmp_asn1.go without requiring a live service.
func TestCMPASN1Helpers(t *testing.T) {
	t.Run("rewrapBodyAsSequence adds UNIVERSAL SEQUENCE header", func(t *testing.T) {
		content := []byte{0x02, 0x01, 0x00} // INTEGER(0)
		wrapped, err := rewrapBodyAsSequence(content)
		require.NoError(t, err)

		// Resulting bytes must be a SEQUENCE.
		var seq asn1.RawValue
		_, err = asn1.Unmarshal(wrapped, &seq)
		require.NoError(t, err)
		assert.Equal(t, asn1.TagSequence, seq.Tag)
		assert.Equal(t, asn1.ClassUniversal, seq.Class)
		assert.True(t, seq.IsCompound)
		assert.Equal(t, content, seq.Bytes)
	})

	t.Run("certHashSHA256 returns correct SHA-256 digest", func(t *testing.T) {
		input := []byte("test-cert-der")
		sum := sha256.Sum256(input)
		got := certHashSHA256(input)
		assert.Equal(t, sum[:], got)
		assert.Len(t, got, 32)
	})

	t.Run("marshalPKIConfBody produces raw NULL payload", func(t *testing.T) {
		der, err := marshalPKIConfBody()
		require.NoError(t, err)
		require.NotEmpty(t, der)

		var rv asn1.RawValue
		_, err = asn1.Unmarshal(der, &rv)
		require.NoError(t, err)
		assert.Equal(t, asn1.TagNull, rv.Tag)
		assert.Equal(t, asn1.ClassUniversal, rv.Class)
		assert.False(t, rv.IsCompound)
	})

	t.Run("marshalErrorBody produces raw ErrorMsgContent sequence", func(t *testing.T) {
		der, err := marshalErrorBody(2, "test error reason")
		require.NoError(t, err)
		require.NotEmpty(t, der)

		var rv asn1.RawValue
		_, err = asn1.Unmarshal(der, &rv)
		require.NoError(t, err)
		assert.Equal(t, asn1.TagSequence, rv.Tag)
		assert.Equal(t, asn1.ClassUniversal, rv.Class)
		assert.True(t, rv.IsCompound)
	})

	t.Run("marshalCertRepBody (IP, tag 1) produces raw CertRepMessage sequence", func(t *testing.T) {
		// Minimal DER certificate for testing - any valid SEQUENCE will do.
		fakeCertDER, _ := asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSequence,
			IsCompound: true,
			Bytes:      []byte{0x02, 0x01, 0x07}, // one INTEGER inside
		})

		der, err := marshalCertRepBody(cmpBodyTagIP, 0, fakeCertDER)
		require.NoError(t, err)

		var rv asn1.RawValue
		_, err = asn1.Unmarshal(der, &rv)
		require.NoError(t, err)
		assert.Equal(t, asn1.TagSequence, rv.Tag)
		assert.Equal(t, asn1.ClassUniversal, rv.Class)
		assert.True(t, rv.IsCompound)
	})

	t.Run("marshalCertRepBody (CP, tag 3) produces raw CertRepMessage sequence", func(t *testing.T) {
		fakeCertDER, _ := asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSequence,
			IsCompound: true,
			Bytes:      []byte{0x02, 0x01, 0x07},
		})

		der, err := marshalCertRepBody(cmpBodyTagCP, 0, fakeCertDER)
		require.NoError(t, err)

		var rv asn1.RawValue
		_, err = asn1.Unmarshal(der, &rv)
		require.NoError(t, err)
		assert.Equal(t, asn1.TagSequence, rv.Tag)
		assert.Equal(t, asn1.ClassUniversal, rv.Class)
	})

	t.Run("hashesEqual is true for equal slices", func(t *testing.T) {
		a := certHashSHA256([]byte("cert"))
		b := certHashSHA256([]byte("cert"))
		assert.True(t, hashesEqual(a, b))
	})

	t.Run("hashesEqual is false for different slices", func(t *testing.T) {
		a := certHashSHA256([]byte("cert-a"))
		b := certHashSHA256([]byte("cert-b"))
		assert.False(t, hashesEqual(a, b))
	})

	t.Run("hashesEqual is false for different lengths", func(t *testing.T) {
		assert.False(t, hashesEqual([]byte{0x01}, []byte{0x01, 0x02}))
	})
}

// --- TransactionIDPresentInSamples verifies that the raw header DER contains
// the expected 16-byte opaque transaction-id value used by the test fixtures.
// This is kept separate because gocmp's PKIHeader decodes it as empty for
// samples that use EXPLICIT rather than IMPLICIT tag encoding for SenderKID
// (which causes subsequent optional-field parsing to stall).  The raw bytes
// prove the values are present in the wire format.
func TestTransactionIDPresentInRawHeaderBytes(t *testing.T) {
	// Transaction IDs extracted via manual asn1.RawValue peeling (hex).
	tests := []struct {
		file  string
		txHex string
	}{
		{"0001.ip", "8591e6c360f6c5f24d1c9ec8e6dc0a8e"},
		{"0002.cr", "85eef5db000859e7e91950b51cfb0e76"},
	}

	for _, tc := range tests {
		t.Run(tc.file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(samplesDir, tc.file))
			require.NoError(t, err)

			block, _ := pem.Decode(data)
			require.NotNil(t, block)

			// The transaction-id is embedded in the raw DER as
			// A4 12 04 10 <16 bytes> (EXPLICIT [4] OCTET STRING).
			wantBytes, _ := hex.DecodeString(tc.txHex)
			require.Len(t, wantBytes, 16)

			// Verify the bytes appear somewhere in the DER
			// (a substring search is sufficient for an opaque ID).
			assert.Contains(t, string(block.Bytes), string(wantBytes),
				"transaction-id bytes must appear in the message DER")
		})
	}
}

// --- SenderNonce presence (raw header scanning) ---

// TestSenderNoncePresentInSamples verifies that each sample PKIHeader carries a
// SenderNonce [5] EXPLICIT OCTET STRING. The caf-pki-local-agent echoes it as
// RecipNonce in every response; a missing nonce breaks replay protection.
//
// Note: gocmp's PKIHeader cannot decode SenderNonce from EXPLICIT-tagged
// samples (SenderKID offset stalls optional-field parsing), so we scan the raw
// PKIHeader SEQUENCE bytes instead of reading msg.Header.SenderNonce directly.
func TestSenderNoncePresentInSamples(t *testing.T) {
	tests := []struct{ file string }{
		{"0001.ip"},
		{"0002.cr"},
	}
	for _, tc := range tests {
		t.Run(tc.file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(samplesDir, tc.file))
			require.NoError(t, err)

			block, _ := pem.Decode(data)
			require.NotNil(t, block)

			// Capture raw PKIHeader bytes (first SEQUENCE element of PKIMessage).
			type rawDispatch struct {
				Header asn1.RawValue
				Body   asn1.RawValue
			}
			var dispatch rawDispatch
			_, err = asn1.Unmarshal(block.Bytes, &dispatch)
			require.NoError(t, err)

			// SenderNonce is encoded as [5] EXPLICIT OCTET STRING inside PKIHeader.
			// pkiHeaderFieldIsNonce returns true when it finds a context-specific
			// tag=5 whose inner value is a non-empty OCTET STRING (distinguishing
			// the nonce from ediPartyName [5] which would contain a SEQUENCE).
			assert.True(t, pkiHeaderFieldIsNonce(dispatch.Header.Bytes, 5),
				"PKIHeader must contain SenderNonce at [5] OCTET STRING")
		})
	}
}

// pkiHeaderFieldIsNonce scans a PKIHeader SEQUENCE content for a
// context-specific field at the given tag whose inner content is a non-empty
// OCTET STRING — the encoding used for transactionID [4] and senderNonce [5].
func pkiHeaderFieldIsNonce(headerBytes []byte, tag int) bool {
	remaining := headerBytes
	for len(remaining) > 0 {
		var field asn1.RawValue
		var err error
		remaining, err = asn1.Unmarshal(remaining, &field)
		if err != nil {
			return false
		}
		if field.Class != asn1.ClassContextSpecific || field.Tag != tag {
			continue
		}
		// EXPLICIT encoding: inner TLV is a universal OCTET STRING.
		var inner asn1.RawValue
		if _, err := asn1.Unmarshal(field.Bytes, &inner); err == nil {
			if inner.Class == asn1.ClassUniversal &&
				inner.Tag == asn1.TagOctetString &&
				len(inner.Bytes) > 0 {
				return true
			}
		}
	}
	return false
}

// --- CertReqID from samples (manual ASN.1 peeling) ---

// TestCertReqIDFromSamples verifies that the certReqId field is a valid
// non-negative integer in each sample. The server echoes it back inside the
// IP/CP response so the client can match the issued certificate to its request.
//
// decodeCertReqMessages (which uses gocmp with IMPLICIT-only tag expectations)
// cannot decode these EXPLICIT-tagged samples from real CMP clients. We use
// the same manual ASN.1 peeling approach as extractSubjectCNFromBody instead.
func TestCertReqIDFromSamples(t *testing.T) {
	tests := []struct{ file string }{
		{"0001.ip"},
		{"0002.cr"},
	}
	for _, tc := range tests {
		t.Run(tc.file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(samplesDir, tc.file))
			require.NoError(t, err)

			block, _ := pem.Decode(data)
			require.NotNil(t, block)

			var msg rawPKIMessage
			_, err = asn1.Unmarshal(block.Bytes, &msg)
			require.NoError(t, err)

			id, err := extractCertReqIDFromBody(msg.Body.Bytes)
			require.NoError(t, err, "certReqId must be present and parseable")
			assert.GreaterOrEqual(t, id, 0, "certReqId must be a non-negative integer")
		})
	}
}

// --- PublicKey parseability from samples (manual ASN.1 peeling) ---

// TestCertTemplatePublicKeyFromSamples verifies that the PublicKey field inside
// the CertTemplate is a valid PKIX SubjectPublicKeyInfo. The caf-pki-local-agent
// calls x509.ParsePKIXPublicKey on it before issuing a certificate; an
// unparseable key causes enrollment to fail.
func TestCertTemplatePublicKeyFromSamples(t *testing.T) {
	tests := []struct{ file string }{
		{"0001.ip"},
		{"0002.cr"},
	}
	for _, tc := range tests {
		t.Run(tc.file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(samplesDir, tc.file))
			require.NoError(t, err)

			block, _ := pem.Decode(data)
			require.NotNil(t, block)

			var msg rawPKIMessage
			_, err = asn1.Unmarshal(block.Bytes, &msg)
			require.NoError(t, err)

			spkiDER, err := extractPublicKeyFromBody(msg.Body.Bytes)
			require.NoError(t, err, "PublicKey [6] must be present in CertTemplate")
			assert.NotEmpty(t, spkiDER)

			pubKey, err := x509.ParsePKIXPublicKey(spkiDER)
			require.NoError(t, err, "CertTemplate.PublicKey must parse as valid PKIX")
			assert.NotNil(t, pubKey)
		})
	}
}

// --- buildResponseHeader nonce/transaction echoing ---

// TestBuildResponseHeader verifies the three invariants the caf-pki-local-agent
// relies on when processing a CMP response:
//  1. TransactionID is echoed unchanged (correlation).
//  2. RecipNonce is set to the request SenderNonce (replay protection).
//  3. A fresh SenderNonce is generated (different from RecipNonce).
func TestBuildResponseHeader(t *testing.T) {
	req := requestPKIHeader{
		PVNO:          pvnoCMP2000,
		TransactionID: []byte{0x01, 0x02, 0x03, 0x04},
		SenderNonce:   []byte{0xAA, 0xBB, 0xCC, 0xDD},
	}

	resp := buildResponseHeader(req)

	assert.Equal(t, pvnoCMP2000, resp.PVNO, "response PVNO must be cmp2000 (2)")

	assert.Equal(t, req.TransactionID, resp.TransactionID,
		"TransactionID must be echoed from request (correlation)")

	assert.Equal(t, req.SenderNonce, resp.RecipNonce,
		"RecipNonce must equal request SenderNonce (replay protection)")

	assert.NotEmpty(t, resp.SenderNonce, "response must include a fresh SenderNonce")
	assert.False(t, bytes.Equal(resp.SenderNonce, resp.RecipNonce),
		"fresh SenderNonce must differ from RecipNonce")
}

// -----------------------------------------------------------------------
// Test-private helpers
// -----------------------------------------------------------------------

// extractCertReqIDFromBody extracts the certReqId integer from the first
// CertReqMessage embedded in the given CMP PKIBody bytes using the same manual
// ASN.1 peeling as extractSubjectCNFromBody (compatible with EXPLICIT encoding).
func extractCertReqIDFromBody(bodyBytes []byte) (int, error) {
	var crMsgsSeq asn1.RawValue
	if _, err := asn1.Unmarshal(bodyBytes, &crMsgsSeq); err != nil {
		return 0, fmt.Errorf("CertReqMessages: %w", err)
	}
	var crMsg asn1.RawValue
	if _, err := asn1.Unmarshal(crMsgsSeq.Bytes, &crMsg); err != nil {
		return 0, fmt.Errorf("CertReqMsg: %w", err)
	}
	var certReqSeq asn1.RawValue
	if _, err := asn1.Unmarshal(crMsg.Bytes, &certReqSeq); err != nil {
		return 0, fmt.Errorf("CertRequest: %w", err)
	}
	var certReqID asn1.RawValue
	if _, err := asn1.Unmarshal(certReqSeq.Bytes, &certReqID); err != nil {
		return 0, fmt.Errorf("certReqId raw: %w", err)
	}
	if certReqID.Tag != asn1.TagInteger || certReqID.Class != asn1.ClassUniversal {
		return 0, fmt.Errorf("expected INTEGER for certReqId, got class=%d tag=%d",
			certReqID.Class, certReqID.Tag)
	}
	var id int
	if _, err := asn1.Unmarshal(certReqID.FullBytes, &id); err != nil {
		return 0, fmt.Errorf("parse certReqId: %w", err)
	}
	return id, nil
}

// extractPublicKeyFromBody extracts the SubjectPublicKeyInfo DER bytes from the
// CertTemplate.PublicKey [6] field in the first CertReqMessage.
// With EXPLICIT encoding (as used by real CMP clients), field.Bytes is the full
// SubjectPublicKeyInfo SEQUENCE DER and can be passed directly to
// x509.ParsePKIXPublicKey.
func extractPublicKeyFromBody(bodyBytes []byte) ([]byte, error) {
	var crMsgsSeq asn1.RawValue
	if _, err := asn1.Unmarshal(bodyBytes, &crMsgsSeq); err != nil {
		return nil, fmt.Errorf("CertReqMessages: %w", err)
	}
	var crMsg asn1.RawValue
	if _, err := asn1.Unmarshal(crMsgsSeq.Bytes, &crMsg); err != nil {
		return nil, fmt.Errorf("CertReqMsg: %w", err)
	}
	var certReqSeq asn1.RawValue
	if _, err := asn1.Unmarshal(crMsg.Bytes, &certReqSeq); err != nil {
		return nil, fmt.Errorf("CertRequest: %w", err)
	}
	// Skip certReqId INTEGER.
	var certReqID asn1.RawValue
	rest, err := asn1.Unmarshal(certReqSeq.Bytes, &certReqID)
	if err != nil {
		return nil, fmt.Errorf("certReqId: %w", err)
	}
	// CertTemplate SEQUENCE.
	var certTemplate asn1.RawValue
	if _, err := asn1.Unmarshal(rest, &certTemplate); err != nil {
		return nil, fmt.Errorf("CertTemplate: %w", err)
	}
	// Scan CertTemplate fields for PublicKey [6].
	// SubjectPublicKeyInfo is a SEQUENCE (not CHOICE), so under IMPLICIT TAGS
	// the [6] tag replaces the outer SEQUENCE tag. field.Bytes therefore holds
	// the SEQUENCE content; we must re-wrap with a UNIVERSAL SEQUENCE header
	// so x509.ParsePKIXPublicKey receives a complete SubjectPublicKeyInfo TLV.
	remaining := certTemplate.Bytes
	for len(remaining) > 0 {
		var field asn1.RawValue
		remaining, err = asn1.Unmarshal(remaining, &field)
		if err != nil {
			return nil, fmt.Errorf("CertTemplate field: %w", err)
		}
		if field.Class == asn1.ClassContextSpecific && field.Tag == 6 {
			wrapped, werr := asn1.Marshal(asn1.RawValue{
				Class:      asn1.ClassUniversal,
				Tag:        asn1.TagSequence,
				IsCompound: true,
				Bytes:      field.Bytes,
			})
			if werr != nil {
				return nil, fmt.Errorf("rewrap SubjectPublicKeyInfo: %w", werr)
			}
			return wrapped, nil
		}
	}
	return nil, fmt.Errorf("PublicKey [6] field not found in CertTemplate")
}

// extractSubjectCNFromBody extracts the CommonName from the Subject field of
// the first CertTemplate embedded in the given CMP PKIBody bytes.
//
// It performs manual asn1.RawValue peeling compatible with both the EXPLICIT
// and IMPLICIT tag variants found in real-world CMP client messages.  It does
// NOT use the gocmp CertTemplate struct, which uses IMPLICIT-only tagging and
// cannot decode messages produced by standard CMP clients (e.g., openssl cmp).
//
// Structure navigated:
//
//	body.Bytes
//	  → CertReqMessages SEQUENCE          (outer explicit wrapper from real clients)
//	    → CertReqMsg SEQUENCE
//	      → CertRequest SEQUENCE
//	        → certReqId INTEGER
//	        → CertTemplate SEQUENCE
//	          → … [5] Subject (context-specific, compound) …
//	            → SEQUENCE (inner RDNSequence)
//	              → SET { SEQUENCE { OID 2.5.4.3, UTF8String } }
func extractSubjectCNFromBody(bodyBytes []byte) (string, error) {
	// Layer 1: strip CertReqMessages SEQUENCE (EXPLICIT encoding from real clients).
	var crMsgsSeq asn1.RawValue
	if _, err := asn1.Unmarshal(bodyBytes, &crMsgsSeq); err != nil {
		return "", fmt.Errorf("CertReqMessages: %w", err)
	}

	// Layer 2: first CertReqMsg SEQUENCE.
	var crMsg asn1.RawValue
	if _, err := asn1.Unmarshal(crMsgsSeq.Bytes, &crMsg); err != nil {
		return "", fmt.Errorf("CertReqMsg: %w", err)
	}

	// Layer 3: CertRequest SEQUENCE (first element of CertReqMsg).
	var certReqSeq asn1.RawValue
	if _, err := asn1.Unmarshal(crMsg.Bytes, &certReqSeq); err != nil {
		return "", fmt.Errorf("CertRequest: %w", err)
	}

	// Layer 4: skip certReqId INTEGER.
	var certReqID asn1.RawValue
	rest, err := asn1.Unmarshal(certReqSeq.Bytes, &certReqID)
	if err != nil {
		return "", fmt.Errorf("certReqId: %w", err)
	}
	if certReqID.Tag != asn1.TagInteger || certReqID.Class != asn1.ClassUniversal {
		return "", fmt.Errorf("expected INTEGER for certReqId, got class=%d tag=%d",
			certReqID.Class, certReqID.Tag)
	}

	// Layer 5: CertTemplate SEQUENCE.
	var certTemplate asn1.RawValue
	if _, err := asn1.Unmarshal(rest, &certTemplate); err != nil {
		return "", fmt.Errorf("CertTemplate: %w", err)
	}
	if certTemplate.Tag != asn1.TagSequence || certTemplate.Class != asn1.ClassUniversal {
		return "", fmt.Errorf("expected UNIVERSAL SEQUENCE for CertTemplate, got class=%d tag=%d",
			certTemplate.Class, certTemplate.Tag)
	}

	// Layer 6: scan CertTemplate fields for Subject [5] (class=context-specific).
	remaining := certTemplate.Bytes
	for len(remaining) > 0 {
		var field asn1.RawValue
		remaining, err = asn1.Unmarshal(remaining, &field)
		if err != nil {
			return "", fmt.Errorf("CertTemplate field: %w", err)
		}
		if field.Class == asn1.ClassContextSpecific && field.Tag == 5 {
			return extractCNFromSubjectBytes(field.Bytes)
		}
	}
	return "", fmt.Errorf("Subject [5] field not found in CertTemplate")
}

// extractCNFromSubjectBytes derives the Common Name from the raw bytes of a
// CertTemplate Subject [5] field.  The bytes may begin with an inner SEQUENCE
// (EXPLICIT) or directly with SET elements (IMPLICIT).
func extractCNFromSubjectBytes(subjectBytes []byte) (string, error) {
	// Strip the inner SEQUENCE wrapping the RDNSequence (present for EXPLICIT encoding).
	var outerSeq asn1.RawValue
	if _, err := asn1.Unmarshal(subjectBytes, &outerSeq); err != nil {
		return "", fmt.Errorf("Subject SEQUENCE: %w", err)
	}

	// OID 2.5.4.3  = id-at-commonName.
	cnOID := asn1.ObjectIdentifier{2, 5, 4, 3}

	rdnBytes := outerSeq.Bytes
	for len(rdnBytes) > 0 {
		var rdnSet asn1.RawValue
		var err error
		rdnBytes, err = asn1.Unmarshal(rdnBytes, &rdnSet)
		if err != nil {
			return "", fmt.Errorf("RDN SET: %w", err)
		}

		// Each SET contains one or more AttributeTypeAndValue SEQUENCEs.
		atvBytes := rdnSet.Bytes
		for len(atvBytes) > 0 {
			var atv asn1.RawValue
			var atvErr error
			atvBytes, atvErr = asn1.Unmarshal(atvBytes, &atv)
			if atvErr != nil {
				break
			}
			// atv.Bytes = OID bytes | value bytes.
			var oid asn1.ObjectIdentifier
			valBytes, err := asn1.Unmarshal(atv.Bytes, &oid)
			if err != nil {
				continue
			}
			if oid.Equal(cnOID) {
				var val asn1.RawValue
				if _, err := asn1.Unmarshal(valBytes, &val); err != nil {
					return "", fmt.Errorf("CN value: %w", err)
				}
				return string(val.Bytes), nil
			}
		}
	}
	return "", fmt.Errorf("OID 2.5.4.3 (CN) not found in Subject")
}
