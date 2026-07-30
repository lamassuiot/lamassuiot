package models

// CMPAuthMode selects how the RA authenticates a CMP enrollment request. It
// mirrors ESTAuthMode's four modes (same names, same string values) since CMP
// supports the same policy shapes as EST, but is kept as its own type so EST
// and CMP DTOs stay independently named.
type CMPAuthMode string

const (
	CMPAuthModeClientCertificate           CMPAuthMode = "CLIENT_CERTIFICATE"
	CMPAuthModeExternalWebhook             CMPAuthMode = "EXTERNAL_WEBHOOK"
	CMPAuthModeClientCertificateAndWebhook CMPAuthMode = "CLIENT_CERTIFICATE_AND_EXTERNAL_WEBHOOK"
	CMPAuthModeNoAuth                      CMPAuthMode = "NO_AUTH"
)

// EnrollmentOptionsLWCRFC9483 holds CMP-specific enrollment settings as defined
// by RFC 9483 (Lightweight CMP Profile) and RFC 4210.
type EnrollmentOptionsLWCRFC9483 struct {
	// AuthMode / AuthOptionsMTLS / AuthOptionsExternalWebhook are the shared
	// enrollment authentication policy. CMP supports the same four modes as EST
	// — NO_AUTH, CLIENT_CERTIFICATE, EXTERNAL_WEBHOOK, and both — validated by
	// the same authenticator. For CMP, CLIENT_CERTIFICATE means the
	// signature-based message-protection signer cert (extraCerts[0], RFC 9483
	// §3.2) rather than a transport mTLS cert.
	AuthMode                   CMPAuthMode                  `json:"auth_mode"`
	AuthOptionsMTLS            AuthOptionsClientCertificate `json:"client_certificate_settings"`
	AuthOptionsExternalWebhook WebhookCall                  `json:"external_webhook_settings"`

	// AcceptImplicit controls whether the server is willing to skip the
	// certConf round-trip when the EE asks for implicit confirmation
	// (id-it-implicitConfirm OID in the request's generalInfo).
	//
	// When true and the EE requested it, the server omits the certConf step
	// and includes id-it-implicitConfirm in the response generalInfo.
	// When false, the server always requires explicit certConf even if the
	// EE asked for implicit (the OID is dropped silently).
	//
	// RFC 9483 §4.1.1 / RFC 4210 §5.2.8.
	AcceptImplicit bool `json:"accept_implicit"`

	// ConfirmationTimeout is the maximum duration the server waits for a
	// certConf message when explicit confirmation is required.
	// RFC 4210 §5.2.8.
	ConfirmationTimeout TimeDuration `json:"confirmation_timeout"`

	// ApprovalTimeout is how long a phased-workflow transaction waits in
	// PENDING for an administrator to approve (or reject) issuance before it
	// is swept by DeleteExpired. Only meaningful when Workflow=phased.
	// When unset/zero the controller falls back to a 7-day default — long
	// enough that an operator has a chance to act, much longer than the
	// per-device certConf window. RFC 4210 §5.3.22 leaves the polling/approval
	// window to server policy.
	ApprovalTimeout TimeDuration `json:"approval_timeout,omitempty"`

	// ProtectionCertificateSerialNumber is the serial number of the end-entity certificate
	// whose key the RA uses to sign CMP response messages (signature-based PKIMessage protection).
	// The key associated with the certificate must be stored in the KMS.
	ProtectionCertificateSerialNumber string `json:"protection_certificate"`

	// EnforcePOPO controls whether the Proof-Of-Possession (POPO) signature inside
	// the CRMF CertReqMsg MUST be verified. RFC 9483 §4.1 requires POPO for ir/cr
	// unless the request is protected by an authorized RA (raVerified) or possession
	// is proven out-of-band (e.g. mTLS provides proof-of-identity+possession at the
	// transport layer). For KUR, the message-level protection IS the POPO per
	// RFC 9483 §4.1.3; when EnforcePOPO is true an unprotected KUR is rejected.
	// Set to false when mTLS or another transport-level mechanism already proves
	// possession so the inner CRMF self-signature is redundant.
	// Defaults to false (Go zero value); set to true to enforce verification.
	EnforcePOPO bool `json:"enforce_popo"`

	// ExpectedAuthenticator is the pre-shared, non-cryptographic answer the CA
	// compares against the RFC 4211 §6.2 id-regCtrl-authenticator control value
	// (e.g. a security-question answer such as a mother's maiden name) when a
	// CertRequest's controls carry that OID. When empty (the default), the
	// Authenticator control is accepted unvalidated — its value is meaningful
	// only to a DMS that has configured an expected answer here. When set, a
	// CertRequest carrying an Authenticator control whose value does not match
	// is rejected with PKIFailureInfo incorrectData (RFC 4211 §6.2).
	//
	// LEGACY: this stores a plaintext shared secret on the DMS, which the
	// nested per-operation schema (IR/CR.AuthenticatorControl below) explicitly
	// avoids — that control carries ONLY a mode, never a value. The plaintext
	// value here is NOT migrated into the nested schema (RFC011 Open Q2). It
	// remains live for cmp_popo.go's existing check; new configuration should
	// prefer the mode-only control once its "required" semantics are designed.
	ExpectedAuthenticator string `json:"expected_authenticator,omitempty"`

	// ServerKeyGenEnabled controls whether this DMS permits RFC 9483 §4.1.6
	// central key generation (CKG): an ir/cr whose CertTemplate carries an
	// empty public key asks the server to generate the key pair itself and
	// return it wrapped in the response. When false (the default), such
	// requests are rejected with PKIFailureInfo notAuthorized instead of
	// generating and delivering a server-side key — operators must opt in
	// per DMS to allow devices to skip on-device key generation.
	//
	// Security tradeoff operators should weigh before enabling this: the
	// generated private key is currently produced with an in-process
	// software crypto engine (crypto/rsa, crypto/ecdsa), not the KMS/HSM
	// engine that backs every other key in this platform (which only ever
	// exposes keys as opaque signing handles and, for HSM-backed engines
	// such as PKCS#11, cannot export a private key at all — that is the
	// point of an HSM). CKG's design requires handing the raw key to the
	// device (encrypted to its recipient certificate), which is fundamentally
	// incompatible with a "keys never leave the engine" backend, so the
	// generated key necessarily exists in this process's memory for the
	// duration of one request, however briefly, regardless of which crypto
	// engine backs everything else on this DMS. Prefer on-device key
	// generation wherever the device is capable of it; reserve CKG for
	// devices that genuinely cannot generate their own keys.
	ServerKeyGenEnabled bool `json:"server_key_gen_enabled,omitempty"`

	// CKGTrustedEncryptionCAs lists the CA IDs a central-key-generation
	// recipient certificate (the certificate the freshly generated private
	// key is encrypted to, RFC 9483 §4.1.6) must chain to. CKG is a more
	// sensitive operation than plain issuance — the RA generates and hands
	// over live key material to whoever it decides to trust as "recipient" —
	// so this is a trust boundary independent of, and by default narrower
	// than, the general AuthMode: even a DMS configured with AuthMode=NO_AUTH
	// (which accepts unauthenticated ir/cr/kur) still requires the CKG
	// recipient certificate to chain-validate. When empty (the default), the
	// DMS's general CMP trust boundary (EnrollmentCA + AuthOptionsMTLS.
	// ValidationCAs + ReEnrollmentSettings.AdditionalValidationCAs — the same
	// set used to validate any other CMP request signer under this DMS) is
	// used, so CKG is never less guarded than ordinary enrollment even before
	// an operator configures this explicitly.
	CKGTrustedEncryptionCAs []string `json:"ckg_trusted_encryption_cas,omitempty"`

	// Workflow selects the CMP transaction lifecycle the DMS follows:
	//   - CMPWorkflowDirect (default): the cert is issued and returned inline
	//     in response to the ir/cr/kur.
	//   - CMPWorkflowPhased: the request is accepted but issuance is deferred
	//     until a PKI administrator approves it. The server returns a "waiting"
	//     response (RFC 9483 §4.4 / RFC 4210 §5.3.22) and the EE retrieves the
	//     certificate via pollReq once approval has happened.
	// Empty is treated as CMPWorkflowDirect.
	Workflow CMPWorkflow `json:"workflow,omitempty"`

	// Nested per-operation CMP settings (RFC 9483). These live ALONGSIDE the
	// flat fields above (the "general" level) and are populated with defaults by
	// ResolveCMPSettings (see dms_cmp_settings.go).
	//
	// These ARE consulted by the request handlers — GENM's access policy and
	// information types, RR's revocation policy, CCR's requester/subject/validity
	// constraints, the per-operation workflow and confirmation overrides, and the
	// CKG allow-lists are all enforced. Only a small, NAMED set of fields still
	// persists without being read; that list lives at the top of
	// dms_cmp_operations.go and is the authoritative one. Treat the "not yet
	// enforced" callouts in
	// docs/rfcs/internal/RFC011-cmp-per-operation-settings.md as design-time
	// history, not current fact.
	IR    CMPIRSettings    `json:"ir"`
	CR    CMPCRSettings    `json:"cr"`
	P10CR CMPP10CRSettings `json:"p10cr"`
	KUR   CMPKURSettings   `json:"kur"`
	RR    CMPRRSettings    `json:"rr"`
	GENM  CMPGENMSettings  `json:"genm"`
	CCR   CMPCCRSettings   `json:"ccr"`
}

// AuthSettings returns the shared authentication policy for this CMP DMS.
func (o EnrollmentOptionsLWCRFC9483) AuthSettings() EnrollmentAuthSettings {
	return EnrollmentAuthSettings{
		AuthMode:                   EnrollmentAuthMode(o.AuthMode),
		AuthOptionsMTLS:            o.AuthOptionsMTLS,
		AuthOptionsExternalWebhook: o.AuthOptionsExternalWebhook,
	}
}

// CMPWorkflow selects the CMP transaction lifecycle a DMS follows. See the
// Workflow field on EnrollmentOptionsLWCRFC9483.
type CMPWorkflow string

const (
	// CMPWorkflowDirect issues the certificate inline (synchronous). This is
	// the default when Workflow is empty.
	CMPWorkflowDirect CMPWorkflow = "direct"
	// CMPWorkflowPhased defers issuance until an administrator approves the
	// transaction; the EE polls for the certificate.
	CMPWorkflowPhased CMPWorkflow = "phased"
)
