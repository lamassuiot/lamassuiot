package models

// CMP per-operation settings (RFC 9483 Lightweight CMP Profile).
//
// This file defines a NESTED, per-operation CMP configuration schema — one
// struct per protocol operation (ir / cr / p10cr / kur / rr / genm / ccr) —
// that lives ALONGSIDE the existing flat EnrollmentOptionsLWCRFC9483 fields
// (see dms_lwcmp_options.go). The flat fields remain the "general" level:
// auth_mode, protection_certificate, enforce_popo, accept_implicit,
// confirmation_timeout, workflow and approval_timeout are read directly by the
// CMP controllers and are the values that policy_overrides.*:inherit resolves
// to. The nested structs below persist and round-trip through create/update/
// get, but — with the deliberate exceptions documented in
// dms_cmp_settings.go (the KUR re-enrollment reshape and the CKG toggle) —
// they are NOT yet consulted by request handlers. See
// docs/rfcs/internal/RFC011-cmp-per-operation-settings.md.
//
// The field/JSON shapes below intentionally match the product spec and the
// Phase-1 dashboard editor (lamassu-dashboard CmpPlannedOperationTabs.tsx) 1:1
// so that when the dashboard binds these controls (Phase 2) the payloads
// round-trip unchanged.

// ---------------------------------------------------------------------------
// Enum types

// CMPOpRegistrationMode selects, per operation, how a device is registered.
// "inherit" defers to the DMS-level EnrollmentSettings.RegistrationMode.
type CMPOpRegistrationMode string

const (
	CMPOpRegistrationModeInherit         CMPOpRegistrationMode = "inherit"
	CMPOpRegistrationModeJITP            CMPOpRegistrationMode = "jitp"
	CMPOpRegistrationModePreRegistration CMPOpRegistrationMode = "pre_registration"
)

// CMPExistingDevicePolicy decides what happens when a request targets an
// already-registered device.
type CMPExistingDevicePolicy string

const (
	CMPExistingDevicePolicyReject  CMPExistingDevicePolicy = "reject"
	CMPExistingDevicePolicyReplace CMPExistingDevicePolicy = "replace"
)

// CMPIdentitySource selects where the device identity is read from when a
// request carries a NULL-DN subject (RFC 9483 §4.1.1).
type CMPIdentitySource string

const (
	CMPIdentitySourceSubjectOnly  CMPIdentitySource = "subject_only"
	CMPIdentitySourceSubjectOrSAN CMPIdentitySource = "subject_or_san"
)

// CMPPOPOMethod names an accepted proof-of-possession technique for ir/cr.
// Values match the dashboard POP_METHOD_OPTIONS.
type CMPPOPOMethod string

const (
	CMPPOPOMethodSignature            CMPPOPOMethod = "signature"
	CMPPOPOMethodTrustedRA            CMPPOPOMethod = "trusted_ra"
	CMPPOPOMethodChallengeResponse    CMPPOPOMethod = "challenge_response"
	CMPPOPOMethodEncryptedCertificate CMPPOPOMethod = "encrypted_certificate"
)

// CMPCKGRecipientMethod names an accepted key-delivery technique for RFC 9483
// §4.1.6 central key generation responses. rsa_key_transport is CMS KTRI;
// ecdh_key_agreement is CMS KARI.
type CMPCKGRecipientMethod string

const (
	CMPCKGRecipientMethodRSAKeyTransport  CMPCKGRecipientMethod = "rsa_key_transport"
	CMPCKGRecipientMethodECDHKeyAgreement CMPCKGRecipientMethod = "ecdh_key_agreement"
)

// CMPControlMode is the tri-state disabled/optional/required policy shared by
// the registration_token and authenticator_control gates.
type CMPControlMode string

const (
	CMPControlModeDisabled CMPControlMode = "disabled"
	CMPControlModeOptional CMPControlMode = "optional"
	CMPControlModeRequired CMPControlMode = "required"
)

// CMPCertificateBehavior distinguishes a cr that adds a parallel certificate
// from one that replaces the device's active certificate.
type CMPCertificateBehavior string

const (
	CMPCertificateBehaviorAdditional CMPCertificateBehavior = "additional"
	CMPCertificateBehaviorReplace    CMPCertificateBehavior = "replace"
)

// CMPKeyPolicy governs whether a kur may reuse the existing public key or must
// present a fresh one.
type CMPKeyPolicy string

const (
	CMPKeyPolicyRequireNew  CMPKeyPolicy = "require_new_key"
	CMPKeyPolicyPermitReuse CMPKeyPolicy = "permit_reuse"
)

// CMPIdentityChangePolicy governs how much of the subject/SAN identity a kur
// may alter relative to the certificate being updated.
type CMPIdentityChangePolicy string

const (
	CMPIdentityChangePolicyForbid        CMPIdentityChangePolicy = "forbid"
	CMPIdentityChangePolicySANOnly       CMPIdentityChangePolicy = "san_only"
	CMPIdentityChangePolicySubjectAndSAN CMPIdentityChangePolicy = "subject_and_san"
)

// CMPRevocationAuthorization selects who may authorize an rr (revocation).
type CMPRevocationAuthorization string

const (
	CMPRevocationAuthorizationSelfOnly      CMPRevocationAuthorization = "self_only"
	CMPRevocationAuthorizationSelfTrustedRA CMPRevocationAuthorization = "self_and_trusted_ra"
)

// CMPRevocationReason is a schema-only allow-list entry mirroring the RFC 5280
// CRLReason names. It is persisted for future rr policy enforcement; the live
// revocation path (LWCRevokeCertificate) does not yet consult it.
type CMPRevocationReason string

const (
	CMPRevocationReasonUnspecified          CMPRevocationReason = "unspecified"
	CMPRevocationReasonKeyCompromise        CMPRevocationReason = "key_compromise"
	CMPRevocationReasonCACompromise         CMPRevocationReason = "ca_compromise"
	CMPRevocationReasonAffiliationChanged   CMPRevocationReason = "affiliation_changed"
	CMPRevocationReasonSuperseded           CMPRevocationReason = "superseded"
	CMPRevocationReasonCessationOfOperation CMPRevocationReason = "cessation_of_operation"
)

// CMPGENMAccessPolicy selects whether genm support messages may be answered
// for unauthenticated callers (discovery) or only for signature-protected
// requests.
type CMPGENMAccessPolicy string

const (
	CMPGENMAccessPolicyPublicDiscovery CMPGENMAccessPolicy = "public_discovery"
	CMPGENMAccessPolicyRequireSigned   CMPGENMAccessPolicy = "require_signed"
)

// CMPCCRWorkflow selects the cross-certification (ccr) lifecycle: issue
// directly, or hold for administrator approval.
type CMPCCRWorkflow string

const (
	CMPCCRWorkflowDirect                CMPCCRWorkflow = "direct"
	CMPCCRWorkflowAdministratorApproval CMPCCRWorkflow = "administrator_approval"
)

// CMPInheritableWorkflow is a policy_overrides.workflow value: "inherit" (use
// the DMS-general Workflow) or an explicit override.
type CMPInheritableWorkflow string

const (
	CMPInheritableWorkflowInherit CMPInheritableWorkflow = "inherit"
	CMPInheritableWorkflowDirect  CMPInheritableWorkflow = "direct"
	CMPInheritableWorkflowPhased  CMPInheritableWorkflow = "phased"
)

// CMPInheritableConfirmation is a policy_overrides.confirmation value:
// "inherit" (use the DMS-general AcceptImplicit/ConfirmationTimeout) or an
// explicit implicit/explicit choice.
type CMPInheritableConfirmation string

const (
	CMPInheritableConfirmationInherit  CMPInheritableConfirmation = "inherit"
	CMPInheritableConfirmationImplicit CMPInheritableConfirmation = "implicit"
	CMPInheritableConfirmationExplicit CMPInheritableConfirmation = "explicit"
)

// ---------------------------------------------------------------------------
// Shared sub-structs

// CMPProofOfPossession configures per-operation POPO acceptance. NOTE: the LIVE
// POPO gate is the DMS-general EnforcePOPO flag (see cmp_popo.go); Required and
// AllowedMethods here persist for future per-operation refinement only.
type CMPProofOfPossession struct {
	Required       bool            `json:"required"`
	AllowedMethods []CMPPOPOMethod `json:"allowed_methods"`
}

// CMPCentralKeyGeneration configures RFC 9483 §4.1.6 CKG per operation. Enabled
// is bridged to the DMS-general ServerKeyGenEnabled toggle by resolution (a
// single shared gate today — see dms_cmp_normalize.go); AllowedRecipientMethods
// persists but is not yet enforced (the wrap mechanism is chosen automatically
// from the recipient certificate's key type).
type CMPCentralKeyGeneration struct {
	Enabled                 bool                    `json:"enabled"`
	AllowedRecipientMethods []CMPCKGRecipientMethod `json:"allowed_recipient_methods"`
}

// CMPControl is the shared tri-state control-gate shape used by ir's
// registration_token and authenticator_control. It stores ONLY a mode — no
// plaintext secret. Persisting the legacy plaintext answer (the
// EnrollmentOptionsLWCRFC9483.ExpectedAuthenticator anti-pattern) into the
// nested schema is intentionally NOT done (RFC011 Open Q2).
type CMPControl struct {
	Mode CMPControlMode `json:"mode"`
}

// CMPPolicyOverrides lets a single operation override the DMS-general workflow
// and confirmation policy, and pin a specific issuance profile. The zero value
// ({inherit, inherit, nil}) defers everything to the general level.
type CMPPolicyOverrides struct {
	Workflow          CMPInheritableWorkflow     `json:"workflow"`
	Confirmation      CMPInheritableConfirmation `json:"confirmation"`
	IssuanceProfileID *string                    `json:"issuance_profile_id"`
}

// CMPSubjectConstraints optionally restricts the subject DN / dNSName SANs a
// cross-certification (ccr) request may ask for. Persisted only; not enforced.
type CMPSubjectConstraints struct {
	AllowedDNPatterns  []string `json:"allowed_dn_patterns"`
	AllowedDNSSuffixes []string `json:"allowed_dns_suffixes"`
}

// CMPTrustedRA scopes which RA certificates a self_and_trusted_ra rr trusts.
// Empty ValidationCAIDs means "use the DMS trust boundary" (trustedRACAIDs).
// RequireCMCRAEKU asks that a trusted RA cert carry the id-kp-cmcRA EKU.
// Persisted only; the live rr trust boundary is computed in dmsmanager_lwcmp.go.
type CMPTrustedRA struct {
	ValidationCAIDs []string `json:"validation_ca_ids"`
	RequireCMCRAEKU bool     `json:"require_cmc_ra_eku"`
}

// ---------------------------------------------------------------------------
// Per-operation structs

// CMPIRSettings configures the Initialization Request (ir, RFC 9483 §4.1.1).
type CMPIRSettings struct {
	Enabled              bool                    `json:"enabled"`
	RegistrationMode     CMPOpRegistrationMode   `json:"registration_mode"`
	ExistingDevicePolicy CMPExistingDevicePolicy `json:"existing_device_policy"`
	IdentitySource       CMPIdentitySource       `json:"identity_source"`
	ProofOfPossession    CMPProofOfPossession    `json:"proof_of_possession"`
	RegistrationToken    CMPControl              `json:"registration_token"`
	AuthenticatorControl CMPControl              `json:"authenticator_control"`
	CentralKeyGeneration CMPCentralKeyGeneration `json:"central_key_generation"`
	PolicyOverrides      CMPPolicyOverrides      `json:"policy_overrides"`
}

// CMPCRSettings configures the Certification Request (cr, RFC 9483 §4.1.2) for a
// device that ALREADY participates in the PKI. It carries the
// additional-vs-replace behaviour and an active-certificate cap.
//
// Persisted-only (no enforcement yet — the backend routes ir and cr through the
// same enrollment service today): RequireExistingDevice, CertificateBehavior,
// MaximumActiveCertificates, AllowedProfileIDs.
type CMPCRSettings struct {
	Enabled                   bool                    `json:"enabled"`
	RequireExistingDevice     bool                    `json:"require_existing_device"`
	CertificateBehavior       CMPCertificateBehavior  `json:"certificate_behavior"`
	MaximumActiveCertificates int                     `json:"maximum_active_certificates"`
	AllowedProfileIDs         []string                `json:"allowed_profile_ids"`
	ProofOfPossession         CMPProofOfPossession    `json:"proof_of_possession"`
	CentralKeyGeneration      CMPCentralKeyGeneration `json:"central_key_generation"`
	PolicyOverrides           CMPPolicyOverrides      `json:"policy_overrides"`
}

// CMPP10CRSettings configures the PKCS#10 Certification Request (p10cr,
// RFC 9483 §4.1.4).
//
// Fixed, non-configurable protocol invariants (documented, not fields):
//   - the PKCS#10 CSR self-signature is ALWAYS verified (it IS the POPO);
//   - there is no CRMF POPO to configure (p10cr carries a bare CSR);
//   - central key generation is NOT available (the client supplies its key);
//   - CRMF registration controls (regToken/authenticator) do not apply.
type CMPP10CRSettings struct {
	Enabled              bool                    `json:"enabled"`
	RegistrationMode     CMPOpRegistrationMode   `json:"registration_mode"`
	ExistingDevicePolicy CMPExistingDevicePolicy `json:"existing_device_policy"`
	AllowedProfileIDs    []string                `json:"allowed_profile_ids"`
	PolicyOverrides      CMPPolicyOverrides      `json:"policy_overrides"`
}

// CMPKURSettings configures the Key Update Request (kur, RFC 9483 §4.1.3).
//
// LIVE fields (reshaped 1:1 onto the shared ReEnrollmentSettings by
// resolution, so existing enforcement honours them):
//   - RenewalWindow               ↔ ReEnrollmentSettings.ReEnrollmentDelta
//   - AllowExpiredCertificate      ↔ ReEnrollmentSettings.EnableExpiredRenewal
//   - AdditionalValidationCAIDs    ↔ ReEnrollmentSettings.AdditionalValidationCAs
//   - RevokeSupersededCertificate  ↔ ReEnrollmentSettings.RevokeOnReEnrollment
//
// Persisted-only (no enforcement yet): KeyPolicy, IdentityChangePolicy,
// PolicyOverrides.
//
// Mandatory, non-configurable protocol invariants (documented, not fields):
// the cert being updated MUST protect the request (RFC 9483 §4.1.3); concurrent
// updates for the same cert are rejected; the old identity stays active until
// confirmation; an unconfirmed new cert is revoked on timeout.
type CMPKURSettings struct {
	Enabled                     bool                    `json:"enabled"`
	RenewalWindow               TimeDuration            `json:"renewal_window"`
	AllowExpiredCertificate     bool                    `json:"allow_expired_certificate"`
	AdditionalValidationCAIDs   []string                `json:"additional_validation_ca_ids"`
	KeyPolicy                   CMPKeyPolicy            `json:"key_policy"`
	IdentityChangePolicy        CMPIdentityChangePolicy `json:"identity_change_policy"`
	RevokeSupersededCertificate bool                    `json:"revoke_superseded_certificate"`
	PolicyOverrides             CMPPolicyOverrides      `json:"policy_overrides"`
}

// CMPRRSettings configures Revocation Requests (rr, RFC 9483 §4.2).
//
// NOTE: an rr is ALWAYS signature-protected — that is a fixed RFC 9483 §5.3.2
// protocol invariant independent of the DMS auth_mode, so there is
// deliberately no "allow unprotected" option here. Authorization/AllowRevival/
// AllowExpiredTarget/AllowedReasons/TrustedRA persist but are not yet enforced;
// the live rr trust boundary is computed in dmsmanager_lwcmp.go
// (LWCRevokeCertificate).
type CMPRRSettings struct {
	Enabled            bool                       `json:"enabled"`
	Authorization      CMPRevocationAuthorization `json:"authorization"`
	AllowRevival       bool                       `json:"allow_revival"`
	AllowExpiredTarget bool                       `json:"allow_expired_target"`
	AllowedReasons     []CMPRevocationReason      `json:"allowed_reasons"`
	TrustedRA          CMPTrustedRA               `json:"trusted_ra"`
}

// CMPGENMInformationTypes gates the individual RFC 9483 §4.3 support messages a
// genm may ask for. The value defaults reflect what Lamassu actually answers
// today (verified in cmp_genmsg.go / dmsmanager_lwcmp.go):
//
//	LIVE (default true):
//	  CACertificates              → id-it-caCerts (LWCCACerts)
//	  SigningKeyTypes             → id-it-signKeyPairTypes (RSA+EC, static)
//	  EncryptionKeyTypes          → id-it-encKeyPairTypes (RSA, static)
//	  PreferredSymmetricAlgorithm → id-it-preferredSymmAlg (AES-256-CBC, static)
//	  SupportedLanguages          → id-it-supportedLangTags ("en", static)
//
//	STUB (default false — service returns nil / not provisioned):
//	  RootCAUpdate                → id-it-rootCaCert  (LWCGetRootCACertUpdate → nil)
//	  CertificateRequestTemplate  → id-it-certReqTemplate (LWCGetCertReqTemplate → nil)
//	  CurrentCRL                  → id-it-currentCRL  (LWCGetCRL → nil)
//	  CRLUpdate                   → id-it-crlStatusList (LWCGetCRL → nil)
//	  ProtocolEncryptionCertificate → id-it-caProtEncCert (not provisioned)
//
// These booleans persist but do NOT yet gate the handler in cmp_genmsg.go.
type CMPGENMInformationTypes struct {
	CACertificates                bool `json:"ca_certificates"`
	SigningKeyTypes               bool `json:"signing_key_types"`
	EncryptionKeyTypes            bool `json:"encryption_key_types"`
	PreferredSymmetricAlgorithm   bool `json:"preferred_symmetric_algorithm"`
	SupportedLanguages            bool `json:"supported_languages"`
	RootCAUpdate                  bool `json:"root_ca_update"`
	CertificateRequestTemplate    bool `json:"certificate_request_template"`
	CurrentCRL                    bool `json:"current_crl"`
	CRLUpdate                     bool `json:"crl_update"`
	ProtocolEncryptionCertificate bool `json:"protocol_encryption_certificate"`
}

// CMPGENMSettings configures General Messages (genm, RFC 9483 §4.3).
type CMPGENMSettings struct {
	Enabled          bool                    `json:"enabled"`
	AccessPolicy     CMPGENMAccessPolicy     `json:"access_policy"`
	InformationTypes CMPGENMInformationTypes `json:"information_types"`
}

// CMPCCRSettings configures Cross-Certification Requests (ccr, RFC 4210bis
// §5.3.11) — a privileged CA-to-CA operation, disabled by default. Entirely
// persisted-only: no ccr policy is enforced from these fields; the live ccr
// path is dmsmanager_lwcmp.go (LWCIssueCrossCertificate), currently always-on
// with no per-DMS gating.
type CMPCCRSettings struct {
	Enabled                  bool                  `json:"enabled"`
	TrustedRequesterCAIDs    []string              `json:"trusted_requester_ca_ids"`
	RequireCACertificate     bool                  `json:"require_ca_certificate"`
	RequireProofOfPossession bool                  `json:"require_proof_of_possession"`
	IssuanceProfileID        string                `json:"issuance_profile_id"`
	MaximumValidity          TimeDuration          `json:"maximum_validity"`
	SubjectConstraints       CMPSubjectConstraints `json:"subject_constraints"`
	Workflow                 CMPCCRWorkflow        `json:"workflow"`
}
