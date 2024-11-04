package services

import (
	"context"
	"crypto/x509"
)

type ESTService interface {
	// CACerts requests a copy of the current CA certificates. See RFC7030 4.1.
	CACerts(ctx context.Context, aps string) ([]*x509.Certificate, error)

	// CSRAttrs requests a list of CA-desired CSR attributes. The returned list
	// may be empty. See RFC7030 4.5.
	//CSRAttrs( aps string, r *http.Request) (CSRAttrs, error)

	// Enroll requests a new certificate. See RFC7030 4.2.
	Enroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error)

	// Reenroll requests renewal/rekey of an existing certificate. See RFC7030
	// 4.2.
	Reenroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error)
	// ServerKeyGen requests a new certificate and a private key. The key must
	// be returned as a DER-encoded PKCS8 PrivateKeyInfo structure if additional
	// encryption is not being employed, or returned inside a CMS SignedData
	// structure which itself is inside a CMS EnvelopedData structure. See
	// RFC7030 4.4.
	ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, interface{}, error)

	// TPMEnroll requests a new certificate using the TPM 2.0 privacy-preserving
	// protocol. An EK certificate chain with a length of at least one must be
	// provided, along with the EK and AK public areas. The return values are an
	// encrypted credential blob, an encrypted seed, and the certificate itself
	// inside a CMS EnvelopedData encrypted with the credential as a pre-shared
	// key.
	//TPMEnroll( csr *x509.CertificateRequest, ekcerts []*x509.Certificate, ekPub, akPub []byte, aps string, r *http.Request) ([]byte, []byte, []byte, error)
}
