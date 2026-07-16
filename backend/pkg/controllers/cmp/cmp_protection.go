package cmp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

type responsePKIMessage struct {
	Header     responsePKIHeader
	Body       asn1.RawValue
	Protection asn1.BitString     `asn1:"explicit,optional,tag:0,omitempty"`
	ExtraCerts []responseCMPCerts `asn1:"explicit,optional,tag:1,omitempty"`
}

type responseCMPCerts struct {
	Raw asn1.RawContent
}

type rawResponsePKIMessage struct {
	Header     asn1.RawValue
	Body       asn1.RawValue
	Protection asn1.RawValue   `asn1:"optional,explicit,tag:0"`
	ExtraCerts []asn1.RawValue `asn1:"optional,explicit,tag:1"`
}

// protectionAlgError flags a verifyRequestProtection failure rooted in the
// protection AlgorithmIdentifier itself (unknown OID, deprecated hash, or
// MAC-based protection). failInfo names the PKIFailureInfo bit the CMP HTTP
// handler should emit: badAlg (0) for an unsupported/unknown algorithm, or
// wrongIntegrity (12) when a MAC-based protection is used where a signature was
// required (RFC 9483 §3.5 — the integrity type is wrong, not the algorithm
// identifier unrecognized). Zero value means badAlg.
type protectionAlgError struct {
	msg      string
	failInfo int
}

func (e *protectionAlgError) Error() string { return e.msg }

// protectionAlgFailInfo returns the PKIFailureInfo bit for err when it is a
// protectionAlgError, and (0, false) otherwise. Used to choose between badAlg,
// wrongIntegrity and badMessageCheck when emitting PKIFailureInfo on
// verification failures.
func protectionAlgFailInfo(err error) (int, bool) {
	var pae *protectionAlgError
	if errors.As(err, &pae) {
		return pae.failInfo, true
	}
	return 0, false
}

// requireClientCertProtection reports whether the DMS auth mode mandates a
// signature-protected (client-certificate) CMP request. CLIENT_CERTIFICATE and
// the combined CLIENT_CERTIFICATE + webhook mode require a signer cert (and
// therefore protection); the other modes (NO_AUTH, EXTERNAL_WEBHOOK) accept
// unsigned messages. Shared by the top-level dispatch and both nested paths.
func requireClientCertProtection(enrollOpts *models.EnrollmentOptionsLWCRFC9483) bool {
	return enrollOpts.AuthMode == models.EnrollmentAuthModeClientCertificate ||
		enrollOpts.AuthMode == models.EnrollmentAuthModeClientCertificateAndWebhook
}

// protectionRejectFailInfo maps a verifyRequestProtection error to the
// PKIFailureInfo bit to emit: a rejected protection AlgorithmIdentifier carries
// its own bit (badAlg / wrongIntegrity via protectionAlgFailInfo); every other
// failure (signature mismatch, missing extraCerts, malformed protection field)
// maps to badMessageCheck (RFC 9810 §5.1.3 / RFC 9483 §3.6.4).
func protectionRejectFailInfo(err error) int {
	failBit := pkiFailureInfoBadMessageCheck
	if algBit, ok := protectionAlgFailInfo(err); ok {
		failBit = algBit
	}
	return failBit
}

// parseLeafExtraCert parses the leaf certificate from a single extraCerts entry
// (ec0), tolerating the encodings Go's asn1 can produce for the [1] EXPLICIT
// SEQUENCE OF Certificate. It tries, in order:
//  1. ec0.FullBytes as a certificate
//  2. the first element inside ec0.Bytes
//  3. ec0.Bytes directly as a legacy fallback
//
// On success it returns the certificate; when all three fail it returns a
// descriptive error (used verbatim by verifyRequestProtection;
// parseFirstExtraCert maps it to a nil result).
func parseLeafExtraCert(ec0 asn1.RawValue) (*x509.Certificate, error) {
	eeCert, err := x509.ParseCertificate(ec0.FullBytes)
	if err != nil {
		// ec0 is likely the SEQUENCE OF wrapper; extract the first element.
		var firstCert asn1.RawValue
		if _, e := asn1.Unmarshal(ec0.Bytes, &firstCert); e == nil {
			if c, e2 := x509.ParseCertificate(firstCert.FullBytes); e2 == nil {
				eeCert = c
				err = nil
			}
		}
	}
	if eeCert == nil {
		var err2 error
		eeCert, err2 = x509.ParseCertificate(ec0.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parse EE certificate from extraCerts[0] (fb=%d,b=%d): fb_err=%v, b_err=%v",
				len(ec0.FullBytes), len(ec0.Bytes), err, err2)
		}
	}
	return eeCert, nil
}

// verifyRequestProtection verifies the signature-based protection of an
// incoming PKIMessage. It uses the public key from the first certificate in
// extraCerts (the EE's protection certificate per RFC 9483 §3.2) to verify
// the Protection BitString over DER(header) || DER(body).
//
// On success it returns the parsed EE certificate so the caller can apply
// further trust checks (ValidationCAs, revocation, RFC 9483 §4.1.3 signer
// binding). When the message carries no protection and required is false,
// the function returns (nil, nil) to signal "unprotected, accepted".
//
// If required is true, the function returns an error when the incoming message
// carries no protection field.
//
// MAC-based protection algorithms (id-PasswordBasedMac, id-DHBasedMac) are
// always rejected regardless of the required flag — only signature-based
// protection (RSA, ECDSA, Ed25519) is supported.
//
// The error returned implements errAlgUnsupported when the rejection is due to
// the protection AlgorithmIdentifier itself (unknown OID, deprecated hash,
// MAC-based) so callers can map it to PKIFailureInfo badAlg per RFC 9810
// §5.1.3 / RFC 9483 §3.6.4.
func verifyRequestProtection(full rawPKIMessageFull, protectionAlg pkix.AlgorithmIdentifier, required bool) (*x509.Certificate, error) {
	protectionAlgOID := protectionAlg.Algorithm

	// A protectionAlg declared in the header with NO accompanying protection
	// value is a structural error regardless of which algorithm is named
	// (RFC 9483 §3.2/§3.5 — missing protection → badMessageCheck). This check
	// MUST run before the MAC-algorithm rejection below: a message that names a
	// MAC algorithm but omits the protection value should be reported as a
	// missing-protection error (badMessageCheck), not as an unsupported
	// algorithm (badAlg).
	if len(full.Protection.Bytes) == 0 {
		if required {
			return nil, fmt.Errorf("request protection absent: DMS configuration requires signature-protected CMP requests")
		}
		return nil, nil
	}

	// Reject MAC-based protection algorithms unconditionally. This is a
	// wrong-integrity-type failure (a MAC where a signature is required), which
	// RFC 9483 §3.5 signals with wrongIntegrity rather than badAlg (the algorithm
	// identifier is understood — it is simply the wrong kind of protection).
	if protectionAlgOID.Equal(oidPasswordBasedMac) || protectionAlgOID.Equal(oidDHBasedMac) {
		return nil, &protectionAlgError{
			msg:      fmt.Sprintf("MAC-based CMP protection (OID %s) is not supported: only signature-based protection is accepted", protectionAlgOID),
			failInfo: pkiFailureInfoWrongIntegrity,
		}
	}

	if len(full.ExtraCerts) == 0 {
		return nil, fmt.Errorf("protection present but extraCerts is empty: cannot identify EE certificate")
	}

	eeCert, err := parseLeafExtraCert(full.ExtraCerts[0])
	if err != nil {
		return nil, err
	}

	payload, err := marshalProtectedPayload(full.Header.FullBytes, full.Body.FullBytes)
	if err != nil {
		return nil, fmt.Errorf("marshal protected payload for verification: %w", err)
	}

	// full.Protection is decoded from the [0] EXPLICIT wrapper as a RawValue.
	// Go's asn1 package does not strip the explicit tag for RawValue fields, so
	// full.Protection holds the outer [0] context-specific value and its
	// Bytes field contains the inner BitString TLV.
	// We need one more level of unmarshalling to reach the actual signature.
	var innerBitString asn1.RawValue
	if _, err := asn1.Unmarshal(full.Protection.Bytes, &innerBitString); err != nil {
		return nil, fmt.Errorf("parse protection BitString: %w", err)
	}
	if innerBitString.Tag != asn1.TagBitString {
		return nil, fmt.Errorf("protection field is not a BitString (tag=%d)", innerBitString.Tag)
	}
	// innerBitString.Bytes = [unused_bits_count, sig_octets...]
	// For whole-byte signatures unused_bits_count is always 0x00.
	if len(innerBitString.Bytes) < 1 {
		return nil, fmt.Errorf("protection BitString is empty")
	}
	protBytes := innerBitString.Bytes[1:] // skip unused-bits byte

	// Derive the hash from the protectionAlg AlgorithmIdentifier declared in
	// the header. For PSS the hash lives inside Parameters, so we must inspect
	// the full AlgorithmIdentifier rather than the OID alone.
	hashAlg, err := hashFromSignatureAlgID(protectionAlg)
	if err != nil {
		return nil, &protectionAlgError{msg: fmt.Sprintf("protection algorithm: %v", err)}
	}

	switch pub := eeCert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if hashAlg == 0 {
			return nil, fmt.Errorf("protection verification failed: ECDSA requires a hash algorithm")
		}
		h := hashAlg.New()
		h.Write(payload)
		if !ecdsa.VerifyASN1(pub, h.Sum(nil), protBytes) {
			return nil, fmt.Errorf("protection verification failed: invalid ECDSA signature")
		}
	case *rsa.PublicKey:
		if hashAlg == 0 {
			return nil, fmt.Errorf("protection verification failed: RSA requires a hash algorithm")
		}
		h := hashAlg.New()
		h.Write(payload)
		digest := h.Sum(nil)
		if protectionAlg.Algorithm.String() == "1.2.840.113549.1.1.10" {
			// RSASSA-PSS: accept any valid salt length the signer chose.
			if err := rsa.VerifyPSS(pub, hashAlg, digest, protBytes, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthAuto,
				Hash:       hashAlg,
			}); err != nil {
				return nil, fmt.Errorf("protection verification failed: %w", err)
			}
		} else {
			if err := rsa.VerifyPKCS1v15(pub, hashAlg, digest, protBytes); err != nil {
				return nil, fmt.Errorf("protection verification failed: %w", err)
			}
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, payload, protBytes) {
			return nil, fmt.Errorf("protection verification failed: invalid Ed25519 signature")
		}
	default:
		return nil, fmt.Errorf("unsupported EE public key type for protection verification: %T", pub)
	}

	return eeCert, nil
}

func marshalProtectedResponse(
	reqHeader requestPKIHeader,
	bodyTag int,
	bodyDER []byte,
	certChain []*x509.Certificate,
	signer crypto.Signer,
) ([]byte, error) {
	if len(certChain) == 0 {
		return nil, fmt.Errorf("marshalProtectedResponse: certChain must not be empty")
	}
	// Ordinary case: the signer IS the leaf (extraCerts[0]).
	return marshalProtectedResponseWithSigner(reqHeader, bodyTag, bodyDER, certChain, certChain[0], signer)
}

// marshalProtectedResponseWithSigner is marshalProtectedResponse with the
// protection signer decoupled from extraCerts[0]. This is needed for RFC 9483
// §4.1.6 KGA responses, where the CMS recipient/originator cert that MUST sit at
// extraCerts[0] (so the compliance validator can match the recipient identifier
// / run key agreement against it) is NOT the certificate whose key signs the
// message protection. signerCert supplies the sender name and senderKID so the
// recipient can still locate the protection certificate within extraCerts.
func marshalProtectedResponseWithSigner(
	reqHeader requestPKIHeader,
	bodyTag int,
	bodyDER []byte,
	extraCertChain []*x509.Certificate,
	signerCert *x509.Certificate,
	signer crypto.Signer,
) ([]byte, error) {
	if len(extraCertChain) == 0 {
		return nil, fmt.Errorf("marshalProtectedResponseWithSigner: extraCertChain must not be empty")
	}
	leaf := signerCert

	protectionAlg, hash, err := cmpProtectionAlgorithm(signer)
	if err != nil {
		return nil, err
	}

	respHeader, err := buildResponseHeader(reqHeader)
	if err != nil {
		return nil, fmt.Errorf("build response header: %w", err)
	}
	respHeader.MessageTime = time.Now().UTC().Round(time.Second)
	respHeader.ProtectionAlg = protectionAlg
	// RFC 9483 §3.1 line 740: "For signature-based protection, MUST be used
	// and contain the value of the SubjectKeyIdentifier if present in the CMP
	// protection certificate". Emit only when the protection cert carries one
	// — RFC 9810 leaves senderKID OPTIONAL when the cert has no SKI extension.
	if len(leaf.SubjectKeyId) > 0 {
		respHeader.SenderKID = leaf.SubjectKeyId
	}
	respSender, err := generalNameDirectoryName(leaf.Subject)
	if err != nil {
		return nil, fmt.Errorf("marshal cmp sender general name: %w", err)
	}
	respHeader.Sender = respSender

	extraCerts := make([]responseCMPCerts, len(extraCertChain))
	for i, c := range extraCertChain {
		extraCerts[i] = responseCMPCerts{Raw: c.Raw}
	}

	msg := responsePKIMessage{
		Header: respHeader,
		Body: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        bodyTag,
			IsCompound: true,
			Bytes:      bodyDER,
		},
		ExtraCerts: extraCerts,
	}

	encoded, err := asn1.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal protected response skeleton: %w", err)
	}

	var rawMsg rawResponsePKIMessage
	if _, err := asn1.Unmarshal(encoded, &rawMsg); err != nil {
		return nil, fmt.Errorf("parse protected response skeleton: %w", err)
	}

	signedData, err := marshalProtectedPayload(rawMsg.Header.FullBytes, rawMsg.Body.FullBytes)
	if err != nil {
		return nil, err
	}

	signature, err := signCMPPayload(signer, hash, signedData)
	if err != nil {
		return nil, err
	}

	msg.Protection = asn1.BitString{
		Bytes:     signature,
		BitLength: len(signature) * 8,
	}

	finalDER, err := asn1.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal protected response: %w", err)
	}
	return finalDER, nil
}

func generalNameDirectoryName(name pkix.Name) (asn1.RawValue, error) {
	type generalName struct {
		RDNSequence pkix.RDNSequence
	}

	fullBytes, err := asn1.MarshalWithParams(generalName{
		RDNSequence: name.ToRDNSequence(),
	}, "tag:4")
	if err != nil {
		return asn1.RawValue{}, err
	}
	return asn1.RawValue{FullBytes: fullBytes}, nil
}

func marshalUnprotectedResponse(reqHeader requestPKIHeader, bodyTag int, bodyDER []byte) ([]byte, error) {
	respHeader, err := buildResponseHeader(reqHeader)
	if err != nil {
		return nil, fmt.Errorf("build response header: %w", err)
	}
	return asn1.Marshal(responsePKIMessage{
		Header: respHeader,
		Body: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        bodyTag,
			IsCompound: true,
			Bytes:      bodyDER,
		},
	})
}

func marshalProtectedPayload(headerDER, bodyDER []byte) ([]byte, error) {
	payload := make([]byte, 0, len(headerDER)+len(bodyDER))
	payload = append(payload, headerDER...)
	payload = append(payload, bodyDER...)
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      payload,
	})
}

func signCMPPayload(signer crypto.Signer, hash crypto.Hash, payload []byte) ([]byte, error) {
	if hash == 0 {
		sig, err := signer.Sign(rand.Reader, payload, crypto.Hash(0))
		if err != nil {
			return nil, fmt.Errorf("sign cmp payload: %w", err)
		}
		return sig, nil
	}

	hasher := hash.New()
	hasher.Write(payload)
	digest := hasher.Sum(nil)

	sig, err := signer.Sign(rand.Reader, digest, hash)
	if err != nil {
		return nil, fmt.Errorf("sign cmp payload: %w", err)
	}
	return sig, nil
}

// cmpProtectionAlgorithm selects the best signature algorithm and hash for
// response protection based on the signer's key type and size.
// For ECDSA it matches the hash to the curve size per RFC 9481 §2.
func cmpProtectionAlgorithm(signer crypto.Signer) (pkix.AlgorithmIdentifier, crypto.Hash, error) {
	switch pub := signer.Public().(type) {
	case *rsa.PublicKey:
		// RSA: SHA-256 is MUST per RFC 9481; use SHA-384/512 for keys > 3072/7680 bits.
		bits := pub.N.BitLen()
		switch {
		case bits > 7680:
			return pkix.AlgorithmIdentifier{
				Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}, // sha512WithRSA
				Parameters: asn1.NullRawValue,
			}, crypto.SHA512, nil
		case bits > 3072:
			return pkix.AlgorithmIdentifier{
				Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}, // sha384WithRSA
				Parameters: asn1.NullRawValue,
			}, crypto.SHA384, nil
		default:
			return pkix.AlgorithmIdentifier{
				Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, // sha256WithRSA
				Parameters: asn1.NullRawValue,
			}, crypto.SHA256, nil
		}
	case *ecdsa.PublicKey:
		// ECDSA: match hash to curve per RFC 9481 §2. Per RFC 5480 §2.1.1 the
		// ECDSA AlgorithmIdentifier MUST omit the parameters field entirely
		// (no NULL) — RFC 9483 §3.2 enforces this for signature-based
		// protection, and the CMP test-suite rejects any parameters here.
		switch pub.Curve.Params().BitSize {
		case 521:
			return pkix.AlgorithmIdentifier{
				Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}, // ecdsaWithSHA512
			}, crypto.SHA512, nil
		case 384:
			return pkix.AlgorithmIdentifier{
				Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}, // ecdsaWithSHA384
			}, crypto.SHA384, nil
		default: // P-256 and anything else
			return pkix.AlgorithmIdentifier{
				Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}, // ecdsaWithSHA256
			}, crypto.SHA256, nil
		}
	case ed25519.PublicKey:
		return pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 3, 101, 112},
		}, 0, nil
	default:
		return pkix.AlgorithmIdentifier{}, 0, fmt.Errorf("unsupported cmp protection key type: %T", signer.Public())
	}
}
