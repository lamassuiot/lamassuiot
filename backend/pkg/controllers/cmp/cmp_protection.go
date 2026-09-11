package cmp

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"

	corecmp "github.com/lamassuiot/lamassuiot/core/v3/pkg/cmp"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

func protectionAlgFailInfo(err error) (int, bool) {
	return corecmp.ProtectionAlgorithmFailureInfo(err)
}

// requireClientCertProtection reports whether the DMS auth mode mandates a
// signature-protected CMP request.
func requireClientCertProtection(enrollOpts *models.CMPEnrollmentSettings) bool {
	return enrollOpts.AuthMode == models.CMPAuthModeClientCertificate ||
		enrollOpts.AuthMode == models.CMPAuthModeClientCertificateAndWebhook
}

// requireProtectionForBody reports whether a message carrying the given PKIBody
// tag must be signature-protected, starting from the DMS's auth_mode default and
// applying the two per-operation rules that override it:
//
//   - rr and kur are ALWAYS protected, on every DMS. For rr the signature is what
//     authorizes the revocation; for kur it is the proof of possession binding the
//     request to the identity being renewed. Neither is a per-DMS toggle, so
//     auth_mode cannot relax them (RFC 9483 §4.1.3 / §4.2).
//   - genm is governed by the separate GENM.AccessPolicy, not auth_mode. That
//     separation is the field's whole purpose: a DMS may require client
//     certificates for enrollment yet still answer capability-discovery genm
//     unauthenticated (RFC 9483 §4.3 / RFC011).
//
// Both the top-level dispatch and the nested-batch pre-check MUST use this: the
// nested path previously applied the auth_mode default uniformly to every inner
// message, so a DMS combining auth_mode=CLIENT_CERTIFICATE with
// GENM.AccessPolicy=public_discovery rejected an entire batch — including any
// valid signed enrollment bundled alongside — over an unsigned genm that would
// have succeeded had it been sent on its own.
func requireProtectionForBody(bodyTag int, enrollOpts *models.CMPEnrollmentSettings) bool {
	switch bodyTag {
	case corecmp.BodyTagRR, corecmp.BodyTagKUR:
		return true
	case corecmp.BodyTagGenMsg:
		return enrollOpts.GENM.AccessPolicy == models.CMPGENMAccessPolicyRequireSigned
	default:
		return requireClientCertProtection(enrollOpts)
	}
}

func protectionRejectFailInfo(err error) int {
	failBit := corecmp.PKIFailureInfoBadMessageCheck
	if algBit, ok := protectionAlgFailInfo(err); ok {
		failBit = algBit
	}
	return failBit
}

func verifyRequestProtection(full corecmp.RawPKIMessageFull, protectionAlg pkix.AlgorithmIdentifier, required bool) (*x509.Certificate, error) {
	return corecmp.VerifyMessageProtection(full, protectionAlg, required)
}

func marshalProtectedResponse(
	reqHeader corecmp.RequestPKIHeader,
	bodyTag int,
	bodyDER []byte,
	certChain []*x509.Certificate,
	signer crypto.Signer,
) ([]byte, error) {
	if len(certChain) == 0 {
		return nil, fmt.Errorf("marshalProtectedResponse: certChain must not be empty")
	}
	return marshalProtectedResponseWithSigner(reqHeader, bodyTag, bodyDER, certChain, certChain[0], signer)
}

// marshalProtectedResponseWithSigner builds the Lamassu response header and
// delegates CMP wire encoding and signing to core/pkg/cmp.
func marshalProtectedResponseWithSigner(
	reqHeader corecmp.RequestPKIHeader,
	bodyTag int,
	bodyDER []byte,
	extraCertChain []*x509.Certificate,
	signerCert *x509.Certificate,
	signer crypto.Signer,
) ([]byte, error) {
	if len(extraCertChain) == 0 {
		return nil, fmt.Errorf("marshalProtectedResponseWithSigner: extraCertChain must not be empty")
	}
	respHeader, err := buildResponseHeader(reqHeader)
	if err != nil {
		return nil, fmt.Errorf("build response header: %w", err)
	}
	respHeader.Sender, err = corecmp.GeneralNameDirectoryName(signerCert.Subject)
	if err != nil {
		return nil, fmt.Errorf("marshal CMP sender GeneralName: %w", err)
	}
	return corecmp.MarshalProtectedMessageWithSigner(respHeader, bodyTag, bodyDER, extraCertChain, signerCert, signer)
}

func marshalUnprotectedResponse(reqHeader corecmp.RequestPKIHeader, bodyTag int, bodyDER []byte) ([]byte, error) {
	respHeader, err := buildResponseHeader(reqHeader)
	if err != nil {
		return nil, fmt.Errorf("build response header: %w", err)
	}
	return corecmp.MarshalUnprotectedMessage(respHeader, bodyTag, bodyDER)
}
