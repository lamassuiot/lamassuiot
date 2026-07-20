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
func requireClientCertProtection(enrollOpts *models.EnrollmentOptionsLWCRFC9483) bool {
	return enrollOpts.AuthMode == models.CMPAuthModeClientCertificate ||
		enrollOpts.AuthMode == models.CMPAuthModeClientCertificateAndWebhook
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
