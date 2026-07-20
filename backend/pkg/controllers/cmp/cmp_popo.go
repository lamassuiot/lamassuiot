package cmp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // RFC 5280 §4.2.1.2 method (1): SKI is defined as SHA-1 of the SPKI bit string.
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/kga"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	software "github.com/lamassuiot/lamassuiot/engines/crypto/software/v3"
	"github.com/sirupsen/logrus"
)

// This file implements the challengeResp proof-of-possession method (RFC
// 9483 §4.1.4 / RFC 4210bis §5.2.8.3): the requester's POPOPrivKey names
// subsequentMessage(challengeResp) instead of furnishing a signature, so the
// CA cannot verify possession from the request alone. Instead it:
//
//  1. generates a random challenge value, encrypts it to the requested public
//     key, and sends it back as popdecc (RFC 4210bis Challenge, the deprecated
//     `challenge` OCTET STRING variant — AES-256-CBC under a key derived from
//     RSA/ECDH — rather than the newer CMS `encryptedRand`);
//  2. parks the request as a PENDING transaction carrying the synthesized CSR
//     and the expected decrypted value, exactly like the phased-workflow
//     admin-approval path parks a request pending a human decision
//     (cmp_enrollment.go's deferForApproval);
//  3. resumes the normal issuance pipeline once the EE proves it decrypted the
//     challenge correctly by replying with popdecr.

// popoChallengeWindow bounds how long a PENDING challengeResp row waits for
// popdecr before it is eligible for cleanup by the same sweep that expires
// ordinary in-flight transactions. A live round trip, not a human decision —
// reuses the certConf window rather than the (much longer) approval window.
const popoChallengeWindow = cmpTxTTL

// popoChallengeFixedIV is the AES-CBC initialization vector used for the
// deprecated `challenge` field (RFC 4210bis §5.2.8.3 version 2 / pvno
// cmp2000). It is a fixed, publicly-known value — confidentiality of the
// challenge comes from the AES key (RSA- or ECDH-derived), not the IV.
var popoChallengeFixedIV = bytes.Repeat([]byte{'A'}, aes.BlockSize)

// oidSHA256Hash is id-sha256 (2.16.840.1.101.3.4.2.1), used as the Challenge
// owf AlgorithmIdentifier.
var oidSHA256Hash = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

// randChallenge is RFC 4210bis's Rand ::= SEQUENCE { int INTEGER, sender
// GeneralName } — the value the CA encrypts into the challenge and the EE
// must decrypt and echo back (as just the integer) in popdecr.
type randChallenge struct {
	Int    *big.Int
	Sender asn1.RawValue
}

// popoChallengeEntry is RFC 4210bis's Challenge ::= SEQUENCE { owf
// AlgorithmIdentifier OPTIONAL, witness OCTET STRING, challenge OCTET STRING
// }. owf/witness let the EE self-check its decryption; Lamassu's own
// verification (in handlePOPODecKeyResp) compares the returned integer
// directly against the value it generated, so witness only needs to be *a*
// hash, not one the EE is required to validate.
type popoChallengeEntry struct {
	OWF       pkix.AlgorithmIdentifier `asn1:"optional"`
	Witness   []byte
	Challenge []byte
}

// randChallengeInt generates a random positive 128-bit integer for use as a
// Rand.int challenge value.
func randChallengeInt() (*big.Int, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("challenge CSPRNG read: %w", err)
	}
	buf[0] &= 0x7F // clear the sign bit so the DER INTEGER encodes unambiguously positive
	return new(big.Int).SetBytes(buf), nil
}

// pkcs7Pad right-pads data to a multiple of blockSize per PKCS#7 (RFC 5652 §6.3).
func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	padded := make([]byte, len(data)+padLen)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}
	return padded
}

// dhDeriveKey is RFC 4210bis's DHBasedMAC key-derivation fallback (also reused
// for the challengeResp ECDH-derived AES key): the base key is truncated when
// it is already long enough, else extended with SHA-256(counter || basekey)
// blocks. For a P-256 ECDH shared secret and desiredLen=32 this is always a
// straight truncation — no hashing — since the shared secret is already 32
// bytes.
func dhDeriveKey(baseKey []byte, desiredLen int) []byte {
	if desiredLen <= len(baseKey) {
		return baseKey[:desiredLen]
	}
	derived := append([]byte{}, baseKey...)
	for i := 1; len(derived) < desiredLen; i++ {
		h := sha256.New()
		fmt.Fprintf(h, "%d", i)
		h.Write(baseKey)
		derived = append(derived, h.Sum(nil)...)
	}
	return derived[:desiredLen]
}

// encryptPOPOChallengeDeprecated encrypts randDER (the DER of a randChallenge)
// for delivery to recipientPub via the deprecated `challenge` OCTET STRING
// method (RFC 4210bis §5.2.8.3 version 2 / pvno cmp2000):
//   - RSA: PKCS#1v1.5-encrypted directly to the recipient's own public key.
//   - ECDSA: AES-256-CBC (fixed IV, PKCS#7 padded) under a key derived from
//     the ECDH shared secret between originatorECDSA and the recipient.
func encryptPOPOChallengeDeprecated(recipientPub crypto.PublicKey, originatorECDSA *ecdsa.PrivateKey, randDER []byte) ([]byte, error) {
	switch pub := recipientPub.(type) {
	case *rsa.PublicKey:
		return rsa.EncryptPKCS1v15(rand.Reader, pub, randDER)
	case *ecdsa.PublicKey:
		if originatorECDSA == nil {
			return nil, fmt.Errorf("no ECDSA originator key available for ECDH")
		}
		origECDH, err := originatorECDSA.ECDH()
		if err != nil {
			return nil, fmt.Errorf("originator key not ECDH-capable: %w", err)
		}
		eeECDH, err := pub.ECDH()
		if err != nil {
			return nil, fmt.Errorf("recipient key not ECDH-capable: %w", err)
		}
		z, err := origECDH.ECDH(eeECDH)
		if err != nil {
			return nil, fmt.Errorf("ECDH: %w", err)
		}
		key := dhDeriveKey(z, 32) // AES-256
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		padded := pkcs7Pad(randDER, aes.BlockSize)
		out := make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, popoChallengeFixedIV).CryptBlocks(out, padded)
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported public key type %T for challenge-response POP", recipientPub)
	}
}

// marshalPOPOChallengeEncryptedRand builds a Challenge entry (RFC 9810 §5.1.3
// update) using the `encryptedRand [0] EXPLICIT EnvelopedData` alternative
// required for pvno cmp2021(3): `challenge` is present but empty, signalling
// to the EE that encryptedRand carries the real value (mirrors
// validate_popdecc_version's is_enc_present/is_not_enc_present distinction in
// the reference client).
func marshalPOPOChallengeEncryptedRand(witness, envelopedDataDER []byte) ([]byte, error) {
	owfDER, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: oidSHA256Hash})
	if err != nil {
		return nil, err
	}
	witnessDER, err := asn1.Marshal(witness)
	if err != nil {
		return nil, err
	}
	emptyChallengeDER, err := asn1.Marshal([]byte{})
	if err != nil {
		return nil, err
	}
	encryptedRandDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: envelopedDataDER,
	})
	if err != nil {
		return nil, err
	}
	var content []byte
	for _, part := range [][]byte{owfDER, witnessDER, emptyChallengeDER, encryptedRandDER} {
		content = append(content, part...)
	}
	return wrapSequenceDER(content, "Challenge")
}

// buildPOPOChallengeEntry builds the DER of a single Challenge entry and, for
// a keyAgreement (ECDSA) recipient, the ECDH originator whose certificate the
// caller MUST use to protect the popdecc response. The delivery method is
// chosen by the request's declared pvno per RFC 9810 §7: cmp2021(3) MUST use
// `encryptedRand` (a CMS EnvelopedData — reusing the exact KTRI/KARI
// primitive buildEncryptedCertRepBody uses for encrCert); anything else falls
// back to the deprecated `challenge` field for cmp2000(2) compatibility.
func (r *cmpHttpRoutes) buildPOPOChallengeEntry(ctx context.Context, lFunc *logrus.Entry, dmsID string, pvno int, recipientPub crypto.PublicKey, recipientPubKeyDER []byte, challengeInt *big.Int, randDER []byte) (entryDER []byte, originator *ecdhOriginator, err error) {
	witness := sha256.Sum256(challengeInt.Bytes())

	if pvno == pvnoCMP2021 {
		technique, terr := kga.TechniqueFor(recipientPub)
		if terr != nil {
			return nil, nil, fmt.Errorf("challengeResp: %w", terr)
		}
		buildIn := kga.BuildInput{
			RecipientCert: &x509.Certificate{PublicKey: recipientPub, SubjectKeyId: computeSKI(recipientPubKeyDER)},
			// RFC 9810 §5.2.8.3.3: the encryptedRand rid MUST be the
			// issuerAndSerialNumber CHOICE with a NULL-DN issuer and the
			// certReqId (always 0 for ir/cr, RFC 9483 §4.1) as serialNumber —
			// the recipient key is not certified yet, so no real identifiers
			// exist for it.
			RecipientRID: &kga.IssuerAndSerial{IssuerDER: emptyRDNSequenceDER(), Serial: big.NewInt(0)},
		}
		if technique == kga.TechniqueKARI {
			originator, err = r.mintECDHOriginator(ctx, lFunc, dmsID)
			if err != nil {
				return nil, nil, fmt.Errorf("challengeResp: %w", err)
			}
			buildIn.KARIOriginatorKey = originator.key
			buildIn.KARIOriginatorCert = originator.cert
		}
		envDataDER, berr := kga.BuildEnvelopedData(randDER, kga.ContentTypeData, buildIn)
		if berr != nil {
			return nil, nil, fmt.Errorf("challengeResp: build EnvelopedData: %w", berr)
		}
		entryDER, err = marshalPOPOChallengeEncryptedRand(witness[:], envDataDER)
		return entryDER, originator, err
	}

	// pvno cmp2000(2) (or unspecified/legacy): the deprecated challenge field.
	var originatorECDSA *ecdsa.PrivateKey
	if _, isEC := recipientPub.(*ecdsa.PublicKey); isEC {
		originator, err = r.mintECDHOriginator(ctx, lFunc, dmsID)
		if err != nil {
			return nil, nil, fmt.Errorf("challengeResp: %w", err)
		}
		originatorECDSA = originator.key
	}
	challengeVal, cerr := encryptPOPOChallengeDeprecated(recipientPub, originatorECDSA, randDER)
	if cerr != nil {
		return nil, nil, fmt.Errorf("challengeResp: encrypt challenge: %w", cerr)
	}
	entryDER, err = asn1.Marshal(popoChallengeEntry{
		OWF:       pkix.AlgorithmIdentifier{Algorithm: oidSHA256Hash},
		Witness:   witness[:],
		Challenge: challengeVal,
	})
	return entryDER, originator, err
}

// handlePOPOChallenge sends popdecc for an ir/cr whose inner POPO named
// subsequentMessage(challengeResp), and parks the request PENDING awaiting
// popdecr. Called from handleEnrollment after every issuance-independent
// validation (regToken, CertTemplate policy, alt CertReq, ...) has already
// passed — the same point issueAndStore would otherwise be invoked from.
func (r *cmpHttpRoutes) handlePOPOChallenge(ctx *gin.Context, lFunc *logrus.Entry, header *requestPKIHeader, req *firstCertReq, dmsID string, enrollOpts *models.EnrollmentOptionsLWCRFC9483, params issueParams) {
	txHex := hex.EncodeToString(header.TransactionID)
	if exists, err := r.store.Exists(ctx.Request.Context(), txHex); err != nil {
		lFunc.Errorf("challengeResp: check existing txID: %v", err)
		r.rejectWithError(ctx, header, PKIStatus(2), "internal error", dmsID, pkiFailureInfoSystemFailure)
		return
	} else if exists {
		lFunc.Warnf("challengeResp: duplicate transactionID %s", txHex)
		r.rejectWithError(ctx, header, PKIStatus(2), "transactionID already in use", dmsID, pkiFailureInfoTransactionIDInUse)
		return
	}

	csr, err := buildSyntheticCSR(req.SubjectDER, req.PublicKeyDER, req.Extensions)
	if err != nil {
		lFunc.Errorf("challengeResp: synthesize CSR: %v", err)
		r.rejectWithError(ctx, header, PKIStatus(2), "cannot build CSR from CertTemplate", dmsID, pkiFailureInfoBadCertTemplate)
		return
	}

	recipientPub, err := x509.ParsePKIXPublicKey(req.PublicKeyDER)
	if err != nil {
		lFunc.Errorf("challengeResp: parse recipient public key: %v", err)
		r.rejectWithError(ctx, header, PKIStatus(2), "malformed public key", dmsID, pkiFailureInfoBadCertTemplate)
		return
	}

	challengeInt, err := randChallengeInt()
	if err != nil {
		lFunc.Errorf("challengeResp: %v", err)
		r.rejectWithError(ctx, header, PKIStatus(2), "internal error", dmsID, pkiFailureInfoSystemFailure)
		return
	}
	randDER, err := asn1.Marshal(randChallenge{Int: challengeInt, Sender: defaultSenderGeneralName()})
	if err != nil {
		lFunc.Errorf("challengeResp: marshal Rand: %v", err)
		r.rejectWithError(ctx, header, PKIStatus(2), "internal error", dmsID, pkiFailureInfoSystemFailure)
		return
	}
	entryDER, originator, err := r.buildPOPOChallengeEntry(ctx.Request.Context(), lFunc, dmsID, header.PVNO, recipientPub, req.PublicKeyDER, challengeInt, randDER)
	if err != nil {
		lFunc.Errorf("challengeResp: %v", err)
		r.rejectWithError(ctx, header, PKIStatus(2), "internal error", dmsID, pkiFailureInfoSystemFailure)
		return
	}
	contentDER, err := asn1.Marshal([]asn1.RawValue{{FullBytes: entryDER}})
	if err != nil {
		lFunc.Errorf("challengeResp: marshal POPODecKeyChallContent: %v", err)
		r.rejectWithError(ctx, header, PKIStatus(2), "internal error", dmsID, pkiFailureInfoSystemFailure)
		return
	}

	if storeErr := r.store.Insert(ctx.Request.Context(), models.CMPTransaction{
		TransactionID:     txHex,
		DMSID:             dmsID,
		State:             models.CMPTransactionStatePending,
		CSR:               (*models.X509CertificateRequest)(csr),
		RequestType:       cmpTagToString(params.requestTag),
		SubjectCommonName: csr.Subject.CommonName,
		WFXJobID:          params.wfxJobID,
		ReceivedNonce:     hex.EncodeToString(header.SenderNonce),
		PopoChallenge:     challengeInt.Text(16),
		ExpiresAt:         time.Now().Add(popoChallengeWindow),
		CreatedAt:         time.Now(),
	}); storeErr != nil {
		lFunc.Errorf("challengeResp: persist pending challenge: %v", storeErr)
		r.rejectWithError(ctx, header, PKIStatus(2), "internal error", dmsID, pkiFailureInfoSystemFailure)
		return
	}

	lFunc.Infof("challengeResp: tx %s parked awaiting popdecr", txHex)
	if originator != nil {
		// Same reasoning as buildEncryptedCertRepBody's protectionOverride: the
		// EE locates its ECDH partner via extraCerts, so popdecc must be signed
		// by (and carry) the minted originator, not the DMS's normal credentials.
		chain := append([]*x509.Certificate{originator.cert}, originator.chain...)
		r.sendRawBodyWithSigner(ctx, lFunc, *header, cmpBodyTagPopDecc, contentDER, chain, originator.key)
		return
	}
	r.sendRawBody(ctx, lFunc, *header, cmpBodyTagPopDecc, contentDER, dmsID)
}

// decodePOPODecKeyRespContent parses a popdecr body — POPODecKeyRespContent
// ::= SEQUENCE OF INTEGER — and returns its first entry. Mirrors the
// single-entry simplification already used for pollReq/certConf (Lamassu
// issues one certificate per transaction, so there is at most one challenge).
func decodePOPODecKeyRespContent(bodyBytes []byte) (*big.Int, error) {
	var ints []*big.Int
	if _, err := asn1.Unmarshal(bodyBytes, &ints); err != nil {
		return nil, fmt.Errorf("POPODecKeyRespContent: %w", err)
	}
	if len(ints) == 0 {
		return nil, fmt.Errorf("POPODecKeyRespContent: empty")
	}
	return ints[0], nil
}

// handlePOPODecKeyResp processes a popdecr (6) body: it validates the EE's
// decrypted challenge against the PENDING transaction parked by
// handlePOPOChallenge and, on success, resumes the normal enrollment pipeline
// from the synthesized CSR stored at challenge time — exactly as
// ApproveCMPTransaction resumes a phased-workflow PENDING row, just triggered
// by a proof-of-possession round trip instead of an administrator.
func (r *cmpHttpRoutes) handlePOPODecKeyResp(ctx *gin.Context, lFunc *logrus.Entry, header requestPKIHeader, body asn1.RawValue, dmsID string, enrollOpts *models.EnrollmentOptionsLWCRFC9483, signerCert *x509.Certificate) {
	submitted, err := decodePOPODecKeyRespContent(body.Bytes)
	if err != nil {
		lFunc.Errorf("popdecr: decode: %v", err)
		r.rejectWithError(ctx, &header, PKIStatus(2), "malformed POPODecKeyRespContent", dmsID, pkiFailureInfoBadDataFormat)
		return
	}

	txHex := hex.EncodeToString(header.TransactionID)
	// SelectAndDelete atomically consumes the PENDING row so a replayed
	// popdecr (or one racing a second, legitimate attempt) cannot resume
	// issuance twice, and so the transactionID is free for issueAndStore's own
	// duplicate check and Insert below.
	tx, ok, err := r.store.SelectAndDelete(ctx.Request.Context(), txHex)
	if err != nil {
		lFunc.Errorf("popdecr: lookup transaction: %v", err)
		r.rejectWithError(ctx, &header, PKIStatus(2), "internal error", dmsID, pkiFailureInfoSystemFailure)
		return
	}
	if !ok || tx.State != models.CMPTransactionStatePending || tx.PopoChallenge == "" || tx.CSR == nil {
		lFunc.Warnf("popdecr: unknown or non-challenge transactionID %s", txHex)
		r.rejectWithError(ctx, &header, PKIStatus(2), "unknown transactionID", dmsID, pkiFailureInfoBadRequest)
		return
	}

	expected, parsed := new(big.Int).SetString(tx.PopoChallenge, 16)
	if !parsed || submitted.Cmp(expected) != 0 {
		lFunc.Warnf("popdecr: challenge mismatch for tx %s", txHex)
		r.rejectWithError(ctx, &header, PKIStatus(2),
			"proof of possession verification failed: challenge response mismatch", dmsID, pkiFailureInfoBadPOP)
		return
	}

	csr := (*x509.CertificateRequest)(tx.CSR)
	req := &firstCertReq{
		CertReqID:    0,
		SubjectDER:   csr.RawSubject,
		PublicKeyDER: csr.RawSubjectPublicKeyInfo,
		Extensions:   csr.Extensions,
	}
	// challengeResp only ever originates from ir/cr (handleEnrollment's
	// variant.verifyInnerPOPO is false for kur), so this two-way choice is
	// exhaustive.
	requestTag := cmpBodyTagCR
	if tx.RequestType == cmpTagToString(cmpBodyTagIR) {
		requestTag = cmpBodyTagIR
	}
	lFunc.Infof("popdecr: challenge verified for tx %s, resuming issuance", txHex)
	r.issueAndStore(ctx, lFunc, &header, req, dmsID, enrollOpts, issueParams{
		requestTag: requestTag,
		respTag:    pollRespTagFor(tx),
		wfxJobID:   tx.WFXJobID,
		presetCSR:  csr,
		enroll: func(c context.Context, csr *x509.CertificateRequest, signerCert *x509.Certificate) (*x509.Certificate, error) {
			return r.svc.LWCEnroll(c, csr, dmsID, signerCert)
		},
	}, signerCert)
}

// This file implements the encrCert proof-of-possession method (RFC 9483
// §4.1.4 / RFC 4210bis §5.2.8.4): instead of a POPOSigningKey signature, the
// requester asks the CA to deliver the issued certificate confidentiality-
// protected to the public key being certified. Only the actual holder of the
// matching private key can decrypt and use it, which is the proof of
// possession — there is no separate round trip (contrast with the
// challengeResp method in cmp_popo_challenge.go, which challenges the EE
// BEFORE issuing).
//
// The wire encoding reuses core/pkg/kga's CMS EnvelopedData primitives
// (KeyTransRecipientInfo for RSA, KeyAgreeRecipientInfo for ECDSA) — the same
// machinery RFC 9483 §4.1.6 central key generation uses to deliver a private
// key, just wrapping the certificate DER directly instead of a KGA-signed
// key package.

// computeSKI derives a SubjectKeyIdentifier from a SubjectPublicKeyInfo DER
// per RFC 5280 §4.2.1.2 method (1): SHA-1 of the subjectPublicKey BIT STRING
// content (excluding tag/length/unused-bits-count) — the same rule Go's own
// certificate issuance falls back to when no explicit SKI is set. Used to
// give the requester's (not-yet-certified) public key a cert-shaped RID for
// the KTRI/KARI recipientInfo; the actual value is never validated by RFC
// 4210bis §5.2.8.4 (there is no issued cert yet to compare against).
func computeSKI(spkiDER []byte) []byte {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spkiDER, &spki); err != nil {
		return nil
	}
	h := sha1.Sum(spki.PublicKey.Bytes) //nolint:gosec
	return h[:]
}

// ecdhOriginator is an ephemeral EC key-agreement identity minted purely to
// run ECDH against a keyAgreement recipient: its certificate must appear in
// the response's extraCerts (conventionally at index 0) so the client can
// locate the ECDH partner (RFC 5652 §6.2.2), and — because the response's own
// protection signature must be verifiable independently of any CMP-level
// device identity — the response itself is signed with this same key rather
// than the DMS's normal protection credentials.
type ecdhOriginator struct {
	key   *ecdsa.PrivateKey
	cert  *x509.Certificate
	chain []*x509.Certificate
}

// mintECDHOriginator issues a short-lived EC key-agreement certificate under
// the DMS's enrollment CA, for use as the ECDH partner in a KeyAgreeRecipientInfo.
//
// The DMS's own CMP response-protection signer cannot be reused for this: it
// is a crypto.Signer that may be backed by an HSM/KMS engine exposing only
// Sign, not raw ECDH — so a fresh, locally-held EC key has to be minted
// instead. This mirrors RFC 9483 §4.1.6 central key generation's KARI
// originator exactly (see handleKGAEnrollment in cmp_enrollment.go), reusing
// the same LWCIssueKGAHelperCertificate / KGAHelperKARIOriginator machinery —
// "ECDH partner certified by this DMS" is the same need in both cases.
func (r *cmpHttpRoutes) mintECDHOriginator(ctx context.Context, lFunc *logrus.Entry, dmsID string) (*ecdhOriginator, error) {
	keyGen, ok := r.svc.(services.LightweightCMPKeyGenerator)
	if !ok {
		return nil, fmt.Errorf("service does not implement LightweightCMPKeyGenerator")
	}
	key, cert, chain, err := mintHelperCert(ctx, lFunc, keyGen, dmsID, "Lamassu CMP ECDH Originator", services.KGAHelperKARIOriginator)
	if err != nil {
		return nil, err
	}
	return &ecdhOriginator{key: key, cert: cert, chain: chain}, nil
}

// mintHelperCert generates an ephemeral P-256 key, self-signs a CSR with
// subjectCN, and has the DMS enrollment CA issue a short-lived KGA helper
// certificate for the given purpose. It is the shared minting sequence behind
// mintECDHOriginator and handleKGAEnrollment's KGA-signer / KARI-originator
// helper certificates: "an EC identity certified by this DMS for a specific
// KGA helper role" is the same need in all three cases.
func mintHelperCert(ctx context.Context, lFunc *logrus.Entry, keyGen services.LightweightCMPKeyGenerator, dmsID, subjectCN string, purpose services.KGAHelperPurpose) (*ecdsa.PrivateKey, *x509.Certificate, []*x509.Certificate, error) {
	sw := software.NewSoftwareCryptoEngine(lFunc)
	_, key, err := sw.CreateECDSAPrivateKey(ctx, elliptic.P256())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate helper key: %w", err)
	}
	csr, err := selfSignedCSR(subjectCN, key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("build helper CSR: %w", err)
	}
	cert, chain, err := keyGen.LWCIssueKGAHelperCertificate(ctx, dmsID, csr, purpose)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("issue helper certificate: %w", err)
	}
	return key, cert, chain, nil
}

// buildEncryptedCertRepBody builds the cp/ip CertRepMessage DER for an
// encrCert response: cert is delivered inside a CMS EnvelopedData addressed
// to recipientPubKeyDER (the CertTemplate's requested — not yet certified —
// public key).
//
// RSA recipients use KeyTransRecipientInfo directly against their own public
// key, so the response can go out signed by the DMS's normal protection
// credentials as usual — the returned protectionOverride is nil. ECDSA
// recipients use KeyAgreeRecipientInfo, which needs a locally-held EC
// originator key to run ECDH against (see mintECDHOriginator); the caller
// MUST send the response protected by the returned override instead of the
// normal sendRawBody path, since extraCerts[0] has to be the originator
// certificate the recipient ECDHs against.
func (r *cmpHttpRoutes) buildEncryptedCertRepBody(ctx context.Context, lFunc *logrus.Entry, dmsID string, certReqID, statusCode int, cert *x509.Certificate, recipientPubKeyDER []byte) (bodyDER []byte, protectionOverride *ecdhOriginator, err error) {
	recipientPub, err := x509.ParsePKIXPublicKey(recipientPubKeyDER)
	if err != nil {
		return nil, nil, fmt.Errorf("encrCert: parse recipient public key: %w", err)
	}

	technique, err := kga.TechniqueFor(recipientPub)
	if err != nil {
		return nil, nil, fmt.Errorf("encrCert: %w", err)
	}

	buildIn := kga.BuildInput{
		RecipientCert: &x509.Certificate{PublicKey: recipientPub, SubjectKeyId: computeSKI(recipientPubKeyDER)},
	}

	if technique == kga.TechniqueKARI {
		originator, err := r.mintECDHOriginator(ctx, lFunc, dmsID)
		if err != nil {
			return nil, nil, fmt.Errorf("encrCert: %w", err)
		}
		buildIn.KARIOriginatorKey = originator.key
		buildIn.KARIOriginatorCert = originator.cert
		protectionOverride = originator
	}

	envDataDER, err := kga.BuildEnvelopedData(cert.Raw, kga.ContentTypeData, buildIn)
	if err != nil {
		return nil, nil, fmt.Errorf("encrCert: build EnvelopedData: %w", err)
	}
	bodyDER, err = marshalCertRepBodyEncrypted(certReqID, statusCode, envDataDER)
	if err != nil {
		return nil, nil, err
	}
	return bodyDER, protectionOverride, nil
}

// popoIndirectKind classifies the POPOPrivKey CHOICE (RFC 4211 §4.1 clause 3 /
// RFC 4210bis §5.2.8) carried inside the keyEncipherment [2] or keyAgreement
// [3] ProofOfPossession alternative — the two "indirect" POP methods where
// possession is proven by a subsequent message rather than a signature.
type popoIndirectKind int

const (
	// popoIndirectUnsupported covers agreeMAC [3] and encryptedKey [4] (not
	// implemented) and any malformed content.
	popoIndirectUnsupported popoIndirectKind = iota
	// popoIndirectEncrCert is subsequentMessage(encrCert): the CA issues
	// normally but delivers the certificate confidentiality-protected to the
	// requested public key (RFC 4210bis §5.2.8.4) — no further round trip.
	popoIndirectEncrCert
	// popoIndirectChallengeResp is subsequentMessage(challengeResp): the CA
	// must challenge the EE to decrypt a random value before issuing
	// (RFC 4210bis §5.2.8.3).
	popoIndirectChallengeResp
)

// classifyPOPOIndirect decodes a POPOPrivKey CHOICE's content (popoRaw.Bytes
// for popoRaw.Tag == 2 (keyEncipherment) or 3 (keyAgreement)) and classifies
// it. Only the subsequentMessage [1] IMPLICIT INTEGER alternative is
// recognized, matching what Lamassu implements.
func classifyPOPOIndirect(popoPrivKeyContent []byte) popoIndirectKind {
	var inner asn1.RawValue
	if _, err := asn1.Unmarshal(popoPrivKeyContent, &inner); err != nil {
		return popoIndirectUnsupported
	}
	if inner.Class != asn1.ClassContextSpecific || inner.Tag != 1 || len(inner.Bytes) != 1 {
		return popoIndirectUnsupported
	}
	// SubsequentMessage ::= INTEGER { encrCert(0), challengeResp(1) }
	switch inner.Bytes[0] {
	case 0:
		return popoIndirectEncrCert
	case 1:
		return popoIndirectChallengeResp
	default:
		return popoIndirectUnsupported
	}
}

// absent and enforce is true the request is rejected. If raVerified [0] is set
// the request is rejected as notAuthorized (see errPOPORAVerifiedFromEE).
// For KUR, POPO is proven implicitly by the message-level protection key being the
// old cert key (RFC 9483 §4.1.3), so this function is NOT called for KUR.
func verifyPOPO(certReqDER []byte, popoRaw asn1.RawValue, pubKeyDER []byte, enforce bool) error {
	isPOPOPresent := len(popoRaw.FullBytes) > 0

	if !isPOPOPresent {
		if enforce {
			return fmt.Errorf("proof of possession (POPO) is required but absent in the certificate request")
		}
		return nil
	}

	switch {
	case popoRaw.Class == asn1.ClassContextSpecific && popoRaw.Tag == 0:
		// raVerified [0] NULL — asserts "an RA already verified POPO". On this
		// endpoint the message-protection signer IS the requester (an EE); there
		// is no trusted-RA path, so an EE asserting raVerified is bypassing POPO
		// and MUST be rejected as notAuthorized (RFC 9483 §4.1 / RFC 4211 §4).
		return errPOPORAVerifiedFromEE

	case popoRaw.Class == asn1.ClassContextSpecific && popoRaw.Tag == 1:
		// signature [1] POPOSigningKey
		return checkPOPOSigningKey(certReqDER, popoRaw.Bytes, pubKeyDER)

	default:
		// keyEncipherment [2] / keyAgreement [3] are not used in the LWC profile.
		if !enforce {
			return nil
		}
		return fmt.Errorf("unsupported POPO type (class=%d tag=%d): only raVerified [0] and signature [1] are supported", popoRaw.Class, popoRaw.Tag)
	}
}

// checkPOPOSigningKey verifies a POPOSigningKey against certReqDER.
//
// POPOSigningKey ::= SEQUENCE {
//
//	poposkInput  [0] POPOSigningKeyInput OPTIONAL,
//	algorithmIdentifier AlgorithmIdentifier,
//	signature   BIT STRING
//
// }
//
// The signature is over the DER encoding of CertRequest (certReqDER).
func checkPOPOSigningKey(certReqDER, poposkContent, pubKeyDER []byte) error {
	remaining := poposkContent

	// Skip optional [0] poposkInput (only present when subject/key absent from certTemplate).
	{
		var first asn1.RawValue
		peek, err := asn1.Unmarshal(remaining, &first)
		if err != nil {
			return fmt.Errorf("POPO: parse first field: %w", err)
		}
		if first.Class == asn1.ClassContextSpecific && first.Tag == 0 {
			remaining = peek // consume the optional poposkInput
		}
	}

	// Parse AlgorithmIdentifier.
	var algID pkix.AlgorithmIdentifier
	rest, err := asn1.Unmarshal(remaining, &algID)
	if err != nil {
		return fmt.Errorf("POPO: parse AlgorithmIdentifier: %w", err)
	}

	// Parse BIT STRING signature.
	var sig asn1.BitString
	if _, err := asn1.Unmarshal(rest, &sig); err != nil {
		return fmt.Errorf("POPO: parse signature: %w", err)
	}

	// Parse the public key from SubjectPublicKeyInfo DER.
	pubKey, err := x509.ParsePKIXPublicKey(pubKeyDER)
	if err != nil {
		return fmt.Errorf("POPO: parse public key: %w", err)
	}

	return popoVerifySignature(certReqDER, sig.Bytes, algID, pubKey)
}

// popoVerifySignature verifies a raw signature over data using the algorithm
// identified by algID. Supports RSA PKCS#1v15, RSASSA-PSS, ECDSA, and Ed25519.
func popoVerifySignature(data, sigBytes []byte, algID pkix.AlgorithmIdentifier, pub crypto.PublicKey) error {
	// Use the AlgorithmIdentifier-aware helper so that id-RSASSA-PSS
	// (OID 1.2.840.113549.1.1.10) resolves its hash from the Parameters
	// SEQUENCE per RFC 4055 §3.1; the OID-only variant rejects PSS.
	hashAlg, err := hashFromSignatureAlgID(algID)
	if err != nil {
		return fmt.Errorf("POPO: %w", err)
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		if hashAlg == 0 {
			return fmt.Errorf("POPO: RSA key with no hash algorithm (OID %s)", algID.Algorithm)
		}
		h := hashAlg.New()
		h.Write(data)
		digest := h.Sum(nil)
		// RFC 4055 §3.1: id-RSASSA-PSS uses RSA-PSS, not PKCS#1 v1.5.
		// PSSOptions{SaltLength: PSSSaltLengthAuto} lets crypto/rsa derive
		// the saltLength from the signature, matching what RFC 9481-compliant
		// clients (OpenSSL, BouncyCastle, etc.) produce.
		if algID.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}) {
			if err := rsa.VerifyPSS(pub, hashAlg, digest, sigBytes, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}); err != nil {
				return fmt.Errorf("POPO: RSA-PSS signature verification failed: %w", err)
			}
			return nil
		}
		if err := rsa.VerifyPKCS1v15(pub, hashAlg, digest, sigBytes); err != nil {
			return fmt.Errorf("POPO: RSA signature verification failed: %w", err)
		}
		return nil

	case *ecdsa.PublicKey:
		if hashAlg == 0 {
			return fmt.Errorf("POPO: ECDSA key with no hash algorithm (OID %s)", algID.Algorithm)
		}
		h := hashAlg.New()
		h.Write(data)
		if !ecdsa.VerifyASN1(pub, h.Sum(nil), sigBytes) {
			return fmt.Errorf("POPO: ECDSA signature verification failed")
		}
		return nil

	case ed25519.PublicKey:
		if !ed25519.Verify(pub, data, sigBytes) {
			return fmt.Errorf("POPO: Ed25519 signature verification failed")
		}
		return nil

	default:
		return fmt.Errorf("POPO: unsupported public key type %T", pub)
	}
}
