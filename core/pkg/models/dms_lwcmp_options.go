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
	ServerKeyGenEnabled bool `json:"server_key_gen_enabled,omitempty"`

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
	// ResolveCMPSettings (see dms_cmp_settings.go). Except for the KUR
	// re-enrollment reshape and the CKG toggle (both bridged to their existing
	// live enforcement by resolution), these persist and round-trip but are
	// not yet consulted by request handlers. See
	// docs/rfcs/internal/RFC011-cmp-per-operation-settings.md.
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
