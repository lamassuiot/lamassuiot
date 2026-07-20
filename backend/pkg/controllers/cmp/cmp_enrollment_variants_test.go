package cmp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"net/http"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// buildIndirectPOPO builds the ProofOfPossession CHOICE for the keyEncipherment
// [2] alternative wrapping a POPOPrivKey whose chosen alternative is
// subsequentMessage [1] IMPLICIT INTEGER (0 = encrCert, 1 = challengeResp).
// RSA test keys always request keyEncipherment (index 2); this package's
// keyAgreement [3] handling (used for EC keys) is structurally identical.
func buildIndirectPOPO(t *testing.T, subsequentMessage int) []byte {
	t.Helper()
	smDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: false,
		Bytes: []byte{byte(subsequentMessage)},
	})
	require.NoError(t, err)
	// POPOPrivKey CHOICE, subsequentMessage alternative — untagged content IS
	// the [1] TLV itself (POPOPrivKey has no separate wrapper).
	popoPrivKey := smDER
	// ProofOfPossession CHOICE, keyEncipherment [2] wraps POPOPrivKey.
	popo, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 2, IsCompound: true, Bytes: popoPrivKey,
	})
	require.NoError(t, err)
	return popo
}

// buildTestIRBodyDERWithIndirectPOPO builds a minimal ir body carrying an
// RSA CertTemplate and a keyEncipherment/subsequentMessage POPO.
func buildTestIRBodyDERWithIndirectPOPO(t *testing.T, cn string, pubKeyDER []byte, subsequentMessage int) []byte {
	t.Helper()
	certRequestDER := buildCertRequestDER(t, cn, pubKeyDER)
	popoDER := buildIndirectPOPO(t, subsequentMessage)
	return ctxDER(t, cmpBodyTagIR, wrapCertReqMsgs(t, certRequestDER, popoDER))
}

func buildTestIRWithIndirectPOPO(t *testing.T, cn string, rsaPub *rsa.PublicKey, subsequentMessage int) (derMsg []byte, txID []byte) {
	t.Helper()
	pubKeyDER, err := x509.MarshalPKIXPublicKey(rsaPub)
	require.NoError(t, err)

	txID = randomTxID(t)
	senderNonce := randomNonce(t)

	headerDER := buildTestPKIHeaderDER(t, txID, senderNonce, nil, false)
	bodyDER := buildTestIRBodyDERWithIndirectPOPO(t, cn, pubKeyDER, subsequentMessage)
	msgDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: concatBytes(headerDER, bodyDER),
	})
	require.NoError(t, err)
	return msgDER, txID
}

// extractEncryptedKeyDER walks CertResponse.certifiedKeyPair.certOrEncCert
// (encryptedCert [1] -> EncryptedKey CHOICE envelopedData [0] -> EnvelopedData)
// and returns the EnvelopedData DER.
func extractEnvelopedDataDER(t *testing.T, responseDER []byte) []byte {
	t.Helper()
	var msg rawPKIMessage
	_, err := asn1.Unmarshal(responseDER, &msg)
	require.NoError(t, err)

	var certRepMsg asn1.RawValue
	_, err = asn1.Unmarshal(msg.Body.Bytes, &certRepMsg)
	require.NoError(t, err)
	var responseSeqOf asn1.RawValue
	_, err = asn1.Unmarshal(certRepMsg.Bytes, &responseSeqOf)
	require.NoError(t, err)
	var firstResp asn1.RawValue
	_, err = asn1.Unmarshal(responseSeqOf.Bytes, &firstResp)
	require.NoError(t, err)

	// certReqId INTEGER, then PKIStatusInfo SEQUENCE, then CertifiedKeyPair.
	var certReqID int
	rest, err := asn1.Unmarshal(firstResp.Bytes, &certReqID)
	require.NoError(t, err)
	var statusInfo asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &statusInfo)
	require.NoError(t, err)
	var certifiedKeyPair asn1.RawValue
	_, err = asn1.Unmarshal(rest, &certifiedKeyPair)
	require.NoError(t, err)

	// CertifiedKeyPair ::= SEQUENCE { certOrEncCert CHOICE, ... }
	var certOrEncCert asn1.RawValue
	_, err = asn1.Unmarshal(certifiedKeyPair.Bytes, &certOrEncCert)
	require.NoError(t, err)
	require.Equal(t, 1, certOrEncCert.Tag, "certOrEncCert must be the encryptedCert [1] alternative")

	// encryptedCert content is the EncryptedKey CHOICE envelopedData [0] alternative.
	var encKeyChoice asn1.RawValue
	_, err = asn1.Unmarshal(certOrEncCert.Bytes, &encKeyChoice)
	require.NoError(t, err)
	require.Equal(t, 0, encKeyChoice.Tag, "EncryptedKey must choose envelopedData [0]")

	// encKeyChoice.Bytes is the EnvelopedData SEQUENCE body (tag was stripped by
	// the [0] IMPLICIT wrapper) — rewrap as a UNIVERSAL SEQUENCE.
	der, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: encKeyChoice.Bytes,
	})
	require.NoError(t, err)
	return der
}

// decryptKTRIEnvelopedData decrypts an EnvelopedData built with a
// KeyTransRecipientInfo (RSA) using rsaKey, returning the plaintext content.
func decryptKTRIEnvelopedData(t *testing.T, envelopedDataDER []byte, rsaKey *rsa.PrivateKey) []byte {
	t.Helper()
	type contentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	var env struct {
		Version              int
		RecipientInfos       asn1.RawValue
		EncryptedContentInfo asn1.RawValue
	}
	_, err := asn1.Unmarshal(envelopedDataDER, &env)
	require.NoError(t, err)

	var recipInfosSet asn1.RawValue
	_, err = asn1.Unmarshal(env.RecipientInfos.FullBytes, &recipInfosSet)
	require.NoError(t, err)
	var ktri asn1.RawValue
	_, err = asn1.Unmarshal(recipInfosSet.Bytes, &ktri)
	require.NoError(t, err)

	// KeyTransRecipientInfo ::= SEQUENCE { version, rid, keyEncryptionAlgorithm, encryptedKey }
	var version int
	rest, err := asn1.Unmarshal(ktri.Bytes, &version)
	require.NoError(t, err)
	var rid asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &rid)
	require.NoError(t, err)
	var keyEncAlg asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &keyEncAlg)
	require.NoError(t, err)
	var encryptedKey []byte
	_, err = asn1.Unmarshal(rest, &encryptedKey)
	require.NoError(t, err)

	// buildKTRI (core/pkg/kga) wraps the CEK with RSA-OAEP/SHA-256, not the
	// legacy PKCS#1 v1.5 encryption scheme.
	cek, err := rsa.DecryptOAEP(sha256.New(), nil, rsaKey, encryptedKey, nil)
	require.NoError(t, err)

	// EncryptedContentInfo ::= SEQUENCE { contentType, contentEncryptionAlgorithm, encryptedContent [0] }
	var eci struct {
		ContentType   asn1.ObjectIdentifier
		ContentEncAlg struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue
		}
		EncryptedContent []byte `asn1:"optional,tag:0"` // IMPLICIT [0] OCTET STRING
	}
	_, err = asn1.Unmarshal(env.EncryptedContentInfo.FullBytes, &eci)
	require.NoError(t, err)

	var iv []byte
	_, err = asn1.Unmarshal(eci.ContentEncAlg.Parameters.FullBytes, &iv)
	require.NoError(t, err)

	block, err := aes.NewCipher(cek)
	require.NoError(t, err)
	require.Equal(t, 0, len(eci.EncryptedContent)%aes.BlockSize)
	out := make([]byte, len(eci.EncryptedContent))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, eci.EncryptedContent)
	padLen := int(out[len(out)-1])
	require.Greater(t, padLen, 0)
	require.LessOrEqual(t, padLen, aes.BlockSize)
	return out[:len(out)-padLen]
}

func TestHandleCMP_EncrCertPOPO_RSA_IssuesEncryptedCert(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	issuedCert, _ := buildSelfSignedCert(t, "encrcert-rsa-device")

	router, _, svc := newEnrollRouter(t, models.EnrollmentOptionsLWCRFC9483{}, issuedCert)
	irDER, _ := buildTestIRWithIndirectPOPO(t, "encrcert-rsa-device", &rsaKey.PublicKey, 0 /* encrCert */)

	resp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, cmpBodyTagIP, parseCMPResponseTag(t, resp.Body.Bytes()),
		"encrCert POPO must be answered inline with ip, no popdecc round trip")

	envDataDER := extractEnvelopedDataDER(t, resp.Body.Bytes())
	plaintext := decryptKTRIEnvelopedData(t, envDataDER, rsaKey)
	decryptedCert, err := x509.ParseCertificate(plaintext)
	require.NoError(t, err, "decrypted content must be the raw issued certificate DER")
	assert.Equal(t, issuedCert.SerialNumber, decryptedCert.SerialNumber)

	svc.AssertExpectations(t)
}

func TestHandleCMP_ChallengeRespPOPO_RSA_FullRoundTrip(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	issuedCert, _ := buildSelfSignedCert(t, "challenge-rsa-device")

	router, store, svc := newEnrollRouter(t, models.EnrollmentOptionsLWCRFC9483{AcceptImplicit: true}, issuedCert)
	irDER, txID := buildTestIRWithIndirectPOPO(t, "challenge-rsa-device", &rsaKey.PublicKey, 1 /* challengeResp */)

	resp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, cmpBodyTagPopDecc, parseCMPResponseTag(t, resp.Body.Bytes()),
		"challengeResp POPO must be answered with popdecc")

	tx, ok := store.Peek(hex.EncodeToString(txID))
	require.True(t, ok, "a PENDING row must be parked awaiting popdecr")
	assert.Equal(t, storage.CMPTransactionStatePending, tx.State)
	require.NotEmpty(t, tx.PopoChallenge)

	// Decrypt the challenge exactly as a compliant EE would.
	challengeVal := extractFirstPOPOChallengeValue(t, resp.Body.Bytes())
	randDER, err := rsa.DecryptPKCS1v15(nil, rsaKey, challengeVal)
	require.NoError(t, err)
	var rand_ struct {
		Int    *big.Int
		Sender asn1.RawValue
	}
	_, err = asn1.Unmarshal(randDER, &rand_)
	require.NoError(t, err)

	expected, ok := new(big.Int).SetString(tx.PopoChallenge, 16)
	require.True(t, ok)
	assert.Equal(t, 0, rand_.Int.Cmp(expected), "decrypted Rand.int must match the server's expected challenge")

	popdecrDER := buildTestPopDecr(t, txID, rand_.Int)
	popdecrResp := postCMP(t, router, "test-dms", popdecrDER)
	require.Equal(t, http.StatusOK, popdecrResp.Code)
	assert.Equal(t, cmpBodyTagIP, parseCMPResponseTag(t, popdecrResp.Body.Bytes()),
		"a correct popdecr must resume issuance and yield ip")

	svc.AssertExpectations(t)
}

func TestHandleCMP_ChallengeRespPOPO_WrongAnswer_Rejected(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	router, _, svc := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{})
	irDER, txID := buildTestIRWithIndirectPOPO(t, "challenge-wrong-device", &rsaKey.PublicKey, 1)

	resp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, cmpBodyTagPopDecc, parseCMPResponseTag(t, resp.Body.Bytes()))

	popdecrDER := buildTestPopDecr(t, txID, big.NewInt(1)) // never the real answer
	popdecrResp := postCMP(t, router, "test-dms", popdecrDER)
	require.Equal(t, http.StatusOK, popdecrResp.Code)
	assert.Equal(t, cmpBodyTagError, parseCMPResponseTag(t, popdecrResp.Body.Bytes()),
		"a wrong popdecr answer must be rejected")
	reason := parseCMPErrorReason(t, popdecrResp.Body.Bytes())
	assert.Contains(t, reason, "challenge response mismatch")
	fi := parseFailInfoBitString(t, popdecrResp.Body.Bytes())
	assert.True(t, bitSet(fi, pkiFailureInfoBadPOP), "failInfo must set badPOP (9)")

	svc.AssertNotCalled(t, "LWCEnroll", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// extractFirstPOPOChallengeValue extracts the `challenge` OCTET STRING of the
// first Challenge entry in a popdecc response body.
func extractFirstPOPOChallengeValue(t *testing.T, responseDER []byte) []byte {
	t.Helper()
	var msg rawPKIMessage
	_, err := asn1.Unmarshal(responseDER, &msg)
	require.NoError(t, err)

	var entries []popoChallengeEntry
	_, err = asn1.Unmarshal(msg.Body.Bytes, &entries)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	return entries[0].Challenge
}

// buildTestPopDecr builds a minimal DER-encoded PKIMessage with a popdecr
// body carrying a single INTEGER.
func buildTestPopDecr(t *testing.T, txID []byte, value *big.Int) []byte {
	t.Helper()
	senderNonce := randomNonce(t)
	headerDER := buildTestPKIHeaderDER(t, txID, senderNonce, nil, false)

	contentDER, err := asn1.Marshal([]*big.Int{value})
	require.NoError(t, err)
	bodyDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: cmpBodyTagPopDecr, IsCompound: true, Bytes: contentDER,
	})
	require.NoError(t, err)
	msgDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: concatBytes(headerDER, bodyDER),
	})
	require.NoError(t, err)
	return msgDER
}

// ---------------------------------------------------------------------------
// p10cr (PKCS#10 certification request, RFC 9483 §4.1.4) handler tests
// ---------------------------------------------------------------------------

// testP10CROptions controls what goes into a test p10cr PKIMessage.
type testP10CROptions struct {
	CN                  string
	TransactionID       []byte
	WithImplicitConfirm bool
	// CorruptSignature flips a byte of the CSR signature so CheckSignature fails.
	CorruptSignature bool
	// ExtraExtensions are embedded in the CSR's extensionRequest attribute.
	ExtraExtensions []pkix.Extension
}

// buildTestP10CR constructs a DER-encoded PKIMessage with a p10cr body carrying
// a genuinely signed PKCS#10 CSR.
func buildTestP10CR(t *testing.T, opts testP10CROptions) (derMsg []byte, txID []byte) {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cn := opts.CN
	if cn == "" {
		cn = "test-p10cr-device"
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: cn},
		ExtraExtensions: opts.ExtraExtensions,
	}, privKey)
	require.NoError(t, err)

	if opts.CorruptSignature {
		// The signature BIT STRING is the last field of the CertificationRequest;
		// flipping the final content byte invalidates it without breaking DER.
		csrDER[len(csrDER)-1] ^= 0xFF
	}

	txID = opts.TransactionID
	if len(txID) == 0 {
		txID = randomTxID(t)
	}
	senderNonce := randomNonce(t)

	headerDER := buildTestPKIHeaderDER(t, txID, senderNonce, nil, opts.WithImplicitConfirm)

	// PKIBody p10cr [4] EXPLICIT CertificationRequest: the [4] wrapper contains
	// the full CSR SEQUENCE TLV.
	bodyDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        cmpBodyTagP10CR,
		IsCompound: true,
		Bytes:      csrDER,
	})
	require.NoError(t, err)

	msgDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      concatBytes(headerDER, bodyDER),
	})
	require.NoError(t, err)
	return msgDER, txID
}

// buildTestCertConfWithReqID is buildTestCertConf with a caller-chosen
// certReqId, needed because p10cr confirmations carry -1 (RFC 4210 Errata 8806).
func buildTestCertConfWithReqID(t *testing.T, txID []byte, certDER []byte, recipNonce []byte, certReqID int) []byte {
	t.Helper()

	senderNonce := randomNonce(t)

	headerDER := buildTestPKIHeaderDER(t, txID, senderNonce, recipNonce, false)

	hash := sha256.Sum256(certDER)
	certStatusDER, err := asn1.Marshal(struct {
		CertHash  []byte
		CertReqID int
	}{
		CertHash:  hash[:],
		CertReqID: certReqID,
	})
	require.NoError(t, err)

	certConfContent, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      certStatusDER,
	})
	require.NoError(t, err)

	bodyDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        cmpBodyTagCertConf,
		IsCompound: true,
		Bytes:      certConfContent,
	})
	require.NoError(t, err)

	msgDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      concatBytes(headerDER, bodyDER),
	})
	require.NoError(t, err)
	return msgDER
}

// parseCertRepCertReqID extracts the certReqId of the first CertResponse in an
// ip/cp/kup response.
func parseCertRepCertReqID(t *testing.T, responseDER []byte) int {
	t.Helper()
	var msg rawPKIMessage
	_, err := asn1.Unmarshal(responseDER, &msg)
	require.NoError(t, err)

	var certRepMsg asn1.RawValue
	_, err = asn1.Unmarshal(msg.Body.Bytes, &certRepMsg)
	require.NoError(t, err)
	var responseSeqOf asn1.RawValue
	_, err = asn1.Unmarshal(certRepMsg.Bytes, &responseSeqOf)
	require.NoError(t, err)
	var firstResp asn1.RawValue
	_, err = asn1.Unmarshal(responseSeqOf.Bytes, &firstResp)
	require.NoError(t, err)

	var certReqID int
	_, err = asn1.Unmarshal(firstResp.Bytes, &certReqID)
	require.NoError(t, err)
	return certReqID
}

// TestHandleCMP_P10CR_IssuesCP verifies the happy path: a signed PKCS#10 CSR in
// a p10cr body yields a cp (3) response with PKIStatus accepted, a certificate
// payload, certReqId -1 (RFC 4210 Errata 8806), and a stored transaction whose
// RequestType is "p10cr".
func TestHandleCMP_P10CR_IssuesCP(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "p10cr-device")

	router, store, svc := newEnrollRouter(t, models.EnrollmentOptionsLWCRFC9483{AcceptImplicit: true}, issuedCert)
	msgDER, txID := buildTestP10CR(t, testP10CROptions{CN: "p10cr-device", WithImplicitConfirm: true})

	resp := postCMP(t, router, "test-dms", msgDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, cmpBodyTagCP, parseCMPResponseTag(t, resp.Body.Bytes()),
		"p10cr must be answered with a cp (3) body")

	status, hasCert := parseIPBodyStatus(t, resp.Body.Bytes())
	assert.Equal(t, pkiStatusAccepted, status)
	assert.True(t, hasCert, "cp must carry the issued certificate")
	assert.Equal(t, p10crCertReqID, parseCertRepCertReqID(t, resp.Body.Bytes()),
		"p10cr response certReqId must be -1 (RFC 4210 Errata 8806)")

	tx, ok := store.Peek(hex.EncodeToString(txID))
	require.True(t, ok, "transaction row must be stored")
	assert.Equal(t, "p10cr", tx.RequestType)
	assert.False(t, tx.IsReenrollment)

	// The service must receive the REAL CSR: its signature verifies (unlike the
	// dummy-signed synthetic CSR the CRMF bodies produce).
	var enrollCSR *x509.CertificateRequest
	for _, call := range svc.Calls {
		if call.Method == "LWCEnroll" {
			enrollCSR = call.Arguments.Get(1).(*x509.CertificateRequest)
		}
	}
	require.NotNil(t, enrollCSR)
	assert.NoError(t, enrollCSR.CheckSignature(), "LWCEnroll must receive the genuinely signed PKCS#10 CSR")

	svc.AssertExpectations(t)
}

// TestHandleCMP_P10CR_ExplicitConfirm verifies the full explicit-confirm
// exchange: p10cr → cp, then certConf carrying certReqId -1 → pkiConf.
func TestHandleCMP_P10CR_ExplicitConfirm(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "p10cr-confirm")

	router, store, _ := newEnrollRouter(t, models.EnrollmentOptionsLWCRFC9483{}, issuedCert)
	msgDER, txID := buildTestP10CR(t, testP10CROptions{CN: "p10cr-confirm"})

	resp := postCMP(t, router, "test-dms", msgDER)
	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, cmpBodyTagCP, parseCMPResponseTag(t, resp.Body.Bytes()))

	sentNonce := peekSentNonce(t, store, txID)

	confDER := buildTestCertConfWithReqID(t, txID, issuedCert.Raw, sentNonce, p10crCertReqID)
	confResp := postCMP(t, router, "test-dms", confDER)
	require.Equal(t, http.StatusOK, confResp.Code)
	assert.Equal(t, cmpBodyTagPKIConf, parseCMPResponseTag(t, confResp.Body.Bytes()),
		"certConf with certReqId -1 must be accepted for a p10cr transaction")
}

// TestHandleCMP_P10CR_CertConf_WrongCertReqID verifies that a certConf carrying
// certReqId 0 for a p10cr transaction is rejected: the p10cr convention is -1.
func TestHandleCMP_P10CR_CertConf_WrongCertReqID(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "p10cr-wrongid")

	router, store, _ := newEnrollRouter(t, models.EnrollmentOptionsLWCRFC9483{}, issuedCert)
	msgDER, txID := buildTestP10CR(t, testP10CROptions{CN: "p10cr-wrongid"})
	resp := postCMP(t, router, "test-dms", msgDER)
	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, cmpBodyTagCP, parseCMPResponseTag(t, resp.Body.Bytes()))

	sentNonce := peekSentNonce(t, store, txID)

	confDER := buildTestCertConfWithReqID(t, txID, issuedCert.Raw, sentNonce, 0)
	confResp := postCMP(t, router, "test-dms", confDER)
	require.Equal(t, http.StatusOK, confResp.Code)
	assert.Equal(t, cmpBodyTagError, parseCMPResponseTag(t, confResp.Body.Bytes()),
		"certConf with certReqId 0 must be rejected for a p10cr transaction")
}

// TestHandleCMP_P10CR_BadSignature verifies that a CSR whose self-signature
// does not verify is rejected in a cp body with failInfo badPOP: the PKCS#10
// signature IS the proof of possession (RFC 9483 §4.1.4).
func TestHandleCMP_P10CR_BadSignature(t *testing.T) {
	router, _, svc := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{})
	msgDER, _ := buildTestP10CR(t, testP10CROptions{CN: "p10cr-badsig", CorruptSignature: true})

	resp := postCMP(t, router, "test-dms", msgDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, cmpBodyTagCP, parseCMPResponseTag(t, resp.Body.Bytes()),
		"POP failure must be reported in a cp CertRepMessage")
	reason, fi := parseCertRepRejection(t, resp.Body.Bytes())
	assert.Contains(t, reason, "proof of possession")
	assert.True(t, bitSet(fi, pkiFailureInfoBadPOP), "failInfo must set badPOP (9)")
	assert.Equal(t, p10crCertReqID, parseCertRepCertReqID(t, resp.Body.Bytes()),
		"rejection certReqId must also be -1 for p10cr")

	svc.AssertNotCalled(t, "LWCEnroll", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestHandleCMP_P10CR_CATemplateRejected verifies the end-entity-only issuance
// policy also applies to p10cr: a CSR requesting BasicConstraints cA=TRUE is
// rejected notAuthorized.
func TestHandleCMP_P10CR_CATemplateRejected(t *testing.T) {
	router, _, svc := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{})

	caBC, err := asn1.Marshal(basicConstraints{IsCA: true})
	require.NoError(t, err)
	msgDER, _ := buildTestP10CR(t, testP10CROptions{
		CN: "p10cr-ca",
		ExtraExtensions: []pkix.Extension{
			{Id: oidExtBasicConstraints, Critical: true, Value: caBC},
		},
	})

	resp := postCMP(t, router, "test-dms", msgDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, cmpBodyTagCP, parseCMPResponseTag(t, resp.Body.Bytes()))
	reason, fi := parseCertRepRejection(t, resp.Body.Bytes())
	assert.Contains(t, reason, "CA certificates")
	assert.True(t, bitSet(fi, pkiFailureInfoNotAuthorized), "failInfo must set notAuthorized (23)")

	svc.AssertNotCalled(t, "LWCEnroll", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestHandleCMP_P10CR_PollReq_DeliversCP verifies lost-response recovery: a
// pollReq against a p10cr transaction re-delivers the certificate in a cp body
// — never an ip — echoing the EE's certReqId (-1).
func TestHandleCMP_P10CR_PollReq_DeliversCP(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "p10cr-poll")

	router, _, _ := newEnrollRouter(t, models.EnrollmentOptionsLWCRFC9483{AcceptImplicit: true}, issuedCert)
	msgDER, txID := buildTestP10CR(t, testP10CROptions{CN: "p10cr-poll", WithImplicitConfirm: true})
	resp := postCMP(t, router, "test-dms", msgDER)
	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, cmpBodyTagCP, parseCMPResponseTag(t, resp.Body.Bytes()))

	pollDER := buildTestPollReq(t, txID, p10crCertReqID)
	pollResp := postCMP(t, router, "test-dms", pollDER)
	require.Equal(t, http.StatusOK, pollResp.Code)
	assert.Equal(t, cmpBodyTagCP, parseCMPResponseTag(t, pollResp.Body.Bytes()),
		"pollReq recovery for a p10cr transaction must deliver a cp, not an ip")
	assert.Equal(t, p10crCertReqID, parseCertRepCertReqID(t, pollResp.Body.Bytes()))
}

// TestP10CRCSRDER_ImplicitTagging verifies the repair path for encoders that
// tag the p10cr CHOICE alternative IMPLICITly (the CertificationRequest
// SEQUENCE tag replaced by [4]).
func TestP10CRCSRDER_ImplicitTagging(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "implicit-tag"},
	}, privKey)
	require.NoError(t, err)

	// EXPLICIT: body content is the full CSR TLV.
	got, err := p10crCSRDER(csrDER)
	require.NoError(t, err)
	assert.Equal(t, csrDER, got)

	// IMPLICIT: body content is the CSR field list without the SEQUENCE tag.
	var outer asn1.RawValue
	_, err = asn1.Unmarshal(csrDER, &outer)
	require.NoError(t, err)
	got, err = p10crCSRDER(outer.Bytes)
	require.NoError(t, err)
	assert.Equal(t, csrDER, got)

	csr, err := x509.ParseCertificateRequest(got)
	require.NoError(t, err)
	assert.Equal(t, "implicit-tag", csr.Subject.CommonName)
}
