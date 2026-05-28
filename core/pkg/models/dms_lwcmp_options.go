package models

// EnrollmentOptionsLWCRFC9483 holds CMP-specific enrollment settings as defined
// by RFC 9483 (Lightweight CMP Profile) and RFC 4210.
type EnrollmentOptionsLWCRFC9483 struct {
	// AuthMode / AuthOptionsMTLS / AuthOptionsExternalWebhook are the shared
	// enrollment authentication policy. CMP supports the same four modes as EST
	// — NO_AUTH, CLIENT_CERTIFICATE, EXTERNAL_WEBHOOK, and both — validated by
	// the same authenticator. For CMP, CLIENT_CERTIFICATE means the
	// signature-based message-protection signer cert (extraCerts[0], RFC 9483
	// §3.2) rather than a transport mTLS cert.
	AuthMode                   EnrollmentAuthMode           `json:"auth_mode"`
	AuthOptionsMTLS            AuthOptionsClientCertificate `json:"client_certificate_settings"`
	AuthOptionsExternalWebhook WebhookCall                  `json:"external_webhook"`

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

	// Workflow selects the CMP transaction lifecycle the DMS follows:
	//   - CMPWorkflowDirect (default): the cert is issued and returned inline
	//     in response to the ir/cr/kur.
	//   - CMPWorkflowPhased: the request is accepted but issuance is deferred
	//     until a PKI administrator approves it. The server returns a "waiting"
	//     response (RFC 9483 §4.4 / RFC 4210 §5.3.22) and the EE retrieves the
	//     certificate via pollReq once approval has happened.
	// Empty is treated as CMPWorkflowDirect.
	Workflow CMPWorkflow `json:"workflow,omitempty"`
}

// AuthSettings returns the shared authentication policy for this CMP DMS.
func (o EnrollmentOptionsLWCRFC9483) AuthSettings() EnrollmentAuthSettings {
	return EnrollmentAuthSettings{
		AuthMode:                   o.AuthMode,
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
