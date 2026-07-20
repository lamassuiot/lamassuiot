package services

import (
	"context"
	"crypto"
	"crypto/x509"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

// LightweightCMPService covers the protocol operations defined by
// RFC 9483 (Lightweight CMP Profile).
//
// The method signatures for Enroll, Reenroll, and CACerts are intentionally
// identical to ESTService so that a DMSManagerService implementation can
// satisfy both interfaces without adapters.
//
// The pkcs10 URI operation (§4.1.4) reuses Enroll at the service level;
// the controller parses the p10cr body and calls Enroll with the resulting
// *x509.CertificateRequest — no separate method is needed.
//
// The nested URI operation (§5.2.2.2) applies only between PKI management
// entities and is out of scope for this interface.
type LightweightCMPService interface {
	// Enroll issues a certificate for a new end-entity (ir / cr / p10cr).
	// RFC 9483 §4.1.1, §4.1.2, §4.1.4.
	LWCEnroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error)

	// Reenroll renews or rekeyes an existing certificate (kur).
	// RFC 9483 §4.1.3.
	LWCReenroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error)

	// CACerts returns the issuing CA certificate chain (genm / caCerts).
	// RFC 9483 §4.3.1.
	LWCCACerts(ctx context.Context, aps string) ([]*x509.Certificate, error)

	// RevokeCertificate requests revocation of a certificate (rr / rp).
	// RFC 9483 §4.2.
	LWCRevokeCertificate(ctx context.Context, input RevokeCertificateInput) error

	// GetRootCACertUpdate returns an updated root CA certificate set
	// (genm id-it-rootCaCert / genp id-it-rootCaKeyUpdate).
	// RFC 9483 §4.3.2.
	//
	// currentRootCert is the root CA certificate the caller currently trusts
	// and wishes to update; it may be nil if no disambiguation is needed.
	// Returns nil when no update is available.
	LWCGetRootCACertUpdate(ctx context.Context, input GetRootCACertUpdateInput) (*RootCACertUpdateOutput, error)

	// GetCertReqTemplate returns a certificate request template describing
	// what the CA requires in certificate requests
	// (genm id-it-certReqTemplate / genp id-it-certReqTemplate).
	// RFC 9483 §4.3.3.
	//
	// Returns nil when the CA imposes no specific requirements.
	LWCGetCertReqTemplate(ctx context.Context, input GetCertReqTemplateInput) (*CertReqTemplateOutput, error)

	// GetCRL returns the latest CRL for the requested issuer
	// (genm id-it-crlStatusList / genp id-it-crls).
	// RFC 9483 §4.3.4.
	//
	// Returns nil when no CRL newer than input.CurrentThisUpdate is available.
	LWCGetCRL(ctx context.Context, input GetCMPCRLInput) (*x509.RevocationList, error)

	// LWCGetEnrollmentOptions returns the CMP enrollment options configured on
	// the DMS identified by aps. The controller uses this to make per-request
	// dispatch decisions such as implicit confirmation mode.
	LWCGetEnrollmentOptions(ctx context.Context, aps string) (*LWCEnrollmentOptions, error)
}

// LightweightCMPProtectionProvider exposes the credentials used to apply
// signature-based protection to CMP responses.
// LWCProtectionCredentials returns the full certificate chain (leaf first,
// root last) and the crypto.Signer for the leaf certificate's private key.
// The chain is placed in the extraCerts field of all protected responses so
// that EE clients can verify the RA's signature without pre-configuring the
// RA certificate.
type LightweightCMPProtectionProvider interface {
	LWCProtectionCredentials(ctx context.Context, aps string) ([]*x509.Certificate, crypto.Signer, error)
}

// LightweightCMPRAValidator authorizes a certificate as a trusted PKI
// management entity (RFC 9483 §5.3.2 / §5.2.3.2) for a given DMS: trust
// requires BOTH the id-kp-cmcRA extendedKeyUsage AND a chain to a CA the DMS
// actually trusts — the EKU alone is a self-issued claim anyone can mint into
// a throwaway self-signed certificate. The CMP controller uses this before
// honouring an ir/cr raVerified POPO claim from a signer other than the EE
// itself, since that claim otherwise lets an unvalidated "RA" skip
// proof-of-possession entirely.
type LightweightCMPRAValidator interface {
	// LWCValidateRASigner returns nil only when signer is a certificate the
	// DMS identified by aps trusts as a PKI management entity.
	LWCValidateRASigner(ctx context.Context, aps string, signer *x509.Certificate) error
}

// LightweightCMPConfirmer commits a deferred re-enrollment (kur) once the EE
// has confirmed the newly issued certificate.
//
// Under RFC 9483 §4.1.3, a key-update is only final after the EE sends certConf
// (or, when implicit confirmation is negotiated, at IP/KUP delivery). Until
// then the device's active identity MUST remain the previous certificate so
// that an unconfirmed update can be rolled back on timeout. LWCReenroll
// therefore only issues the new certificate; the identity bind and supersession
// of the previous certificate are deferred to LWCConfirmReenrollment, which the
// CMP controller invokes from handleCertConf (explicit) or immediately after
// issuance (implicit confirm).
type LightweightCMPConfirmer interface {
	// LWCConfirmReenrollment binds the newly issued certificate (identified by
	// its hex serial number) as the device's active identity and supersedes the
	// previously active certificate. aps is the DMS id. It is safe to call more
	// than once for the same serial.
	LWCConfirmReenrollment(ctx context.Context, aps string, certSerialNumber string) error
}

// KGAHelperPurpose selects which kind of ephemeral helper certificate the CMP
// controller needs the service to issue for an RFC 9483 §4.1.6 central key
// generation response.
type KGAHelperPurpose int

const (
	// KGAHelperSigner is the KGA signing certificate: it carries the
	// id-kp-cmKGA extendedKeyUsage and signs the CMS SignedData that wraps the
	// centrally generated key. It must chain to a trust anchor.
	KGAHelperSigner KGAHelperPurpose = iota
	// KGAHelperKARIOriginator is the EC key-agreement originator certificate
	// used for the KARI technique: it must carry keyAgreement (and
	// digitalSignature, since it also signs the CMP response protection so it
	// lands as extraCerts[0], which the recipient runs ECDH against).
	KGAHelperKARIOriginator
)

// LightweightCMPKeyGenerator provides RFC 9483 §4.1.6 central key generation
// support at the service layer: it issues the short-lived helper certificates a
// KGA response needs, from the DMS's enrollment CA, WITHOUT registering a device
// or binding an identity. The controller generates the corresponding private
// keys in memory (software engine) and supplies a self-signed CSR.
type LightweightCMPKeyGenerator interface {
	// LWCIssueKGAHelperCertificate signs csr under the enrollment CA of the DMS
	// identified by aps, using an issuance profile appropriate to purpose, and
	// returns the issued leaf certificate together with its issuing chain
	// (leaf-exclusive, root last) for embedding in the KGA SignedData so the
	// recipient can validate the signer up to a trust anchor.
	LWCIssueKGAHelperCertificate(ctx context.Context, aps string, csr *x509.CertificateRequest, purpose KGAHelperPurpose) (*x509.Certificate, []*x509.Certificate, error)
}

// LightweightCMPCrossCertifier provides CMP cross-certification (ccr/ccp,
// RFC 4210bis §5.3.11): the DMS's enrollment CA issues a certificate for
// another CA's key/subject (as described by the request CertTemplate). The
// controller performs the CMP-level authorization (the requester must
// authenticate as a CA) and CertTemplate validation before calling this.
type LightweightCMPCrossCertifier interface {
	// LWCIssueCrossCertificate signs csr under the enrollment CA of the DMS
	// identified by aps and returns the issued cross-certificate together with
	// its issuing chain (leaf-exclusive, root last) for the ccp response.
	//
	// reqNotBefore / reqNotAfter carry the validity requested in the ccr
	// CertTemplate (RFC 4210bis App. D.6 requires the validity field). When
	// non-nil they are honoured: the requested notBefore is applied as-is and the
	// requested notAfter is honoured up to the profile's maximum cross-cert
	// lifetime (capped, never extended). When nil, the profile default is used.
	LWCIssueCrossCertificate(ctx context.Context, aps string, csr *x509.CertificateRequest, reqNotBefore, reqNotAfter *time.Time) (*x509.Certificate, []*x509.Certificate, error)
}

// LWCEnrollmentOptions is returned by LWCGetEnrollmentOptions and carries the
// DMS-level CMP settings the controller needs to make dispatch decisions
// (e.g. whether implicit confirmation is allowed).
// The controller must not cache this value across requests.
type LWCEnrollmentOptions = models.EnrollmentOptionsLWCRFC9483

// ---------------------------------------------------------------------------
// RevokeCertificate

// RevokeCertificateInput carries the parameters for a CMP revocation
// request (rr body).
type RevokeCertificateInput struct {
	// APS is the DMS identifier, taken from the well-known URI path component.
	APS string `validate:"required"`

	// SerialNumber is the hex-encoded serial number of the certificate to revoke.
	SerialNumber string `validate:"required"`

	// Reason is the RFC 5280 / X.509 revocation reason code carried in the rr body.
	Reason models.RevocationReason
}

// ---------------------------------------------------------------------------
// GetRootCACertUpdate

// GetRootCACertUpdateInput carries the parameters for a root CA certificate
// update request (genm id-it-rootCaCert, RFC 9483 §4.3.2).
type GetRootCACertUpdateInput struct {
	// APS is the DMS identifier.
	APS string `validate:"required"`

	// CurrentRootCert is the root CA certificate the caller currently trusts.
	// SHOULD be provided when needed for unique identification; may be nil.
	CurrentRootCert *x509.Certificate
}

// RootCACertUpdateOutput holds the up-to-three certificates returned in a
// genp id-it-rootCaKeyUpdate response (RFC 9483 §4.3.2).
// The entire value is nil when no update is available.
type RootCACertUpdateOutput struct {
	// NewWithNew is the new root CA certificate signed by the new key. REQUIRED.
	NewWithNew *x509.Certificate

	// NewWithOld is the new root CA public key signed by the old private key.
	// Needed by EEs that currently trust the old root CA. REQUIRED.
	NewWithOld *x509.Certificate

	// OldWithNew is the old root CA public key signed by the new private key.
	// Only needed in rare rollover scenarios. OPTIONAL.
	OldWithNew *x509.Certificate
}

// ---------------------------------------------------------------------------
// GetCertReqTemplate

// GetCertReqTemplateInput carries the parameters for a certificate request
// template query (genm id-it-certReqTemplate, RFC 9483 §4.3.3).
type GetCertReqTemplateInput struct {
	// APS is the DMS identifier.
	APS string `validate:"required"`

	// CertProfile optionally names the requested certificate profile,
	// carried in the id-it-certProfile generalInfo header field.
	CertProfile string
}

// CertReqTemplateOutput holds the content of a genp id-it-certReqTemplate
// response (RFC 9483 §4.3.3).
// The entire value is nil when the CA imposes no requirements.
type CertReqTemplateOutput struct {
	// Subject is the required/template Subject distinguished name.
	// An empty pkix.Name signals that the EE must fill in its own subject.
	Subject x509.Certificate

	// AllowedKeyAlgorithms lists the public key algorithms the CA accepts.
	// Empty means any algorithm is acceptable.
	AllowedKeyAlgorithms []x509.PublicKeyAlgorithm
}

// ---------------------------------------------------------------------------
// GetCRL

// GetCMPCRLInput carries the parameters for a CRL update request
// (genm id-it-crlStatusList, RFC 9483 §4.3.4).
type GetCMPCRLInput struct {
	// APS is the DMS identifier.
	APS string `validate:"required"`

	// IssuerName identifies the CA whose CRL is requested.
	// The EE must provide either IssuerName or CAID.
	IssuerName string

	// CAID is the Lamassu internal CA identifier for the requested CRL.
	CAID string

	// CurrentThisUpdate is the thisUpdate time of the most recent CRL the
	// caller already has. When non-zero, a new CRL is returned only if a
	// more recent one is available; otherwise nil is returned.
	CurrentThisUpdate time.Time
}
