package models

// CMP per-operation settings (RFC 9483 Lightweight CMP Profile).
//
// This file defines a NESTED, per-operation CMP configuration schema — one
// struct per protocol operation (ir / cr / p10cr / kur / rr / genm / ccr) —
// that lives ALONGSIDE the existing flat CMPEnrollmentSettings fields
// (see dms_lwcmp_options.go). The flat fields remain the "general" level:
// auth_mode, protection_certificate, enforce_popo, accept_implicit,
// confirmation_timeout, workflow and approval_timeout are read directly by the
// CMP controllers and are the values that policy_overrides.*:inherit resolves
// to.
//
// As of a manual protocol-conformance audit (openssl cmp against a live
// server, cross-referenced with the code), essentially every field below IS
// consulted by request handlers — the schema is not "mostly aspirational" the
// way earlier revisions of this comment implied. The confirmed, NAMED
// exceptions — fields that genuinely persist and round-trip but are not yet
// read by any handler — are:
//   - CMPCCRSettings.IssuanceProfileID (cross-certification issuance profile
//     selection does not yet consult this)
//   - CMPIRSettings.IdentitySource (subject_only vs subject_or_san selection is
//     not implemented; the NULL-DN identity source is fixed)
//   - CMPKURSettings.PolicyOverrides.IssuanceProfileID specifically: kur's
//     Workflow/Confirmation overrides ARE live (same shared enrollment
//     pipeline as ir/cr/p10cr — see EffectiveWorkflow/EffectiveAcceptImplicit
//     below), but resolveCMPIssuanceProfile's per-operation profile-override
//     switch in dmsmanager_lwcmp.go only has cases for ir/cr/p10cr.
// See docs/rfcs/internal/RFC011-cmp-per-operation-settings.md for the original
// design rationale; treat its "not yet enforced" callouts as superseded by
// this comment and the per-struct notes below, not as current fact.
//
// The field/JSON shapes below intentionally match the product spec and the
// dashboard editor (lamassu-dashboard CmpPlannedOperationTabs.tsx) 1:1 so that
// dashboard-authored payloads round-trip unchanged.

// ---------------------------------------------------------------------------
// Enum types

// CMPIdentitySource selects where the device identity is read from when a
// request carries a NULL-DN subject (RFC 9483 §4.1.1). NOT YET enforced — see
// the top-of-file note on IR.IdentitySource.
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

// CMPRevocationReason mirrors the RFC 5280 CRLReason names accepted by an rr's
// AllowedReasons allow-list. LIVE: LWCRevokeCertificate rejects a revocation
// whose requested reason isn't in the DMS's RR.AllowedReasons.
type CMPRevocationReason string

const (
	CMPRevocationReasonUnspecified          CMPRevocationReason = "unspecified"
	CMPRevocationReasonKeyCompromise        CMPRevocationReason = "key_compromise"
	CMPRevocationReasonCACompromise         CMPRevocationReason = "ca_compromise"
	CMPRevocationReasonAffiliationChanged   CMPRevocationReason = "affiliation_changed"
	CMPRevocationReasonSuperseded           CMPRevocationReason = "superseded"
	CMPRevocationReasonCessationOfOperation CMPRevocationReason = "cessation_of_operation"
	// CMPRevocationReasonPrivilegeWithdrawn is CRLReason 9.
	CMPRevocationReasonPrivilegeWithdrawn CMPRevocationReason = "privilege_withdrawn"
	// CMPRevocationReasonAACompromise is CRLReason 10.
	CMPRevocationReasonAACompromise CMPRevocationReason = "aa_compromise"
)

// Note: there is deliberately NO name for certificateHold (6) or removeFromCRL
// (8). Both belong to the suspend/resume lifecycle governed by RR.AllowRevival
// rather than to this list of permanent revocation reasons — see
// cmpRevocationReasonName in dmsmanager_lwcmp.go for the full rationale. Adding
// one here would silently start gating it.

// CMPGENMAccessPolicy selects whether genm support messages may be answered
// for unauthenticated callers (discovery) or only for signature-protected
// requests.
type CMPGENMAccessPolicy string

const (
	CMPGENMAccessPolicyPublicDiscovery CMPGENMAccessPolicy = "public_discovery"
	CMPGENMAccessPolicyRequireSigned   CMPGENMAccessPolicy = "require_signed"
)

// CMPPreferredSymmetricAlgorithm selects which symmetric content-encryption
// algorithm the CA advertises in the genm id-it-preferredSymmAlg response
// (RFC 4210bis §5.3.19.4). It is the algorithm an EE should use when it must
// encrypt content for the CA (e.g. the KGA private-key transport wrapper).
// Only AES variants are offered for now.
type CMPPreferredSymmetricAlgorithm string

const (
	CMPPreferredSymmetricAlgorithmAES128CBC CMPPreferredSymmetricAlgorithm = "aes128_cbc"
	CMPPreferredSymmetricAlgorithmAES192CBC CMPPreferredSymmetricAlgorithm = "aes192_cbc"
	CMPPreferredSymmetricAlgorithmAES256CBC CMPPreferredSymmetricAlgorithm = "aes256_cbc"
	CMPPreferredSymmetricAlgorithmAES128GCM CMPPreferredSymmetricAlgorithm = "aes128_gcm"
	CMPPreferredSymmetricAlgorithmAES192GCM CMPPreferredSymmetricAlgorithm = "aes192_gcm"
	CMPPreferredSymmetricAlgorithmAES256GCM CMPPreferredSymmetricAlgorithm = "aes256_gcm"
)

// CMPCCRWorkflow selects the cross-certification (ccr) lifecycle: issue
// directly, or hold for administrator approval.
type CMPCCRWorkflow string

const (
	CMPCCRWorkflowDirect                CMPCCRWorkflow = "direct"
	CMPCCRWorkflowAdministratorApproval CMPCCRWorkflow = "administrator_approval"
)

// CMPCCRRequesterMode makes CCR.TrustedRequesterCAIDs' effect explicit instead
// of overloading "list is empty" to mean "unrestricted": that conflated two
// distinct intents ("never configured" and "deliberately deny everyone") into
// one representation, so an empty-but-not-yet-populated list silently failed
// open. Any preserves today's behavior (RequireCACertificate is the only
// gate); Restricted requires the signer to chain to a listed CA — and, with
// an empty list, authorizes no one.
type CMPCCRRequesterMode string

const (
	CMPCCRRequesterModeAny        CMPCCRRequesterMode = "any"
	CMPCCRRequesterModeRestricted CMPCCRRequesterMode = "restricted"
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

// CMPProofOfPossession configures per-operation POPO acceptance for ir/cr
// (selected by body tag via cmpProofOfPossessionFor). LIVE: AllowedMethods
// gates which POPO technique a request may use (verifyPOPO/popoMethodAllowed
// reject a signature/raVerified/encrCert/challengeResp POPO absent from this
// list with notAuthorized); Required gates whether an ABSENT POPO is tolerated
// (verifyPOPO's `enforce` argument). The DMS-general EnforcePOPO flag is a
// SEPARATE, narrower gate: it only requires message-level signature protection
// on a kur (RFC 9483 §4.1.3), and does not affect ir/cr at all.
type CMPProofOfPossession struct {
	Required       bool            `json:"required"`
	AllowedMethods []CMPPOPOMethod `json:"allowed_methods"`
}

// CMPCentralKeyGeneration configures RFC 9483 §4.1.6 CKG per operation. Enabled
// is bridged to the DMS-general ServerKeyGenEnabled toggle by resolution (a
// single shared gate today — see dms_cmp_normalize.go).
//
// AllowedRecipientMethods is LIVE: the CMS wrap technique (KTRI vs KARI) is
// auto-selected from the recipient certificate's key type, and
// ckgRecipientMethodAllowed in cmp_enrollment.go then rejects the request when
// the selected technique is absent from this allow-list. Note an EMPTY list
// permits nothing rather than everything.
type CMPCentralKeyGeneration struct {
	Enabled                 bool                    `json:"enabled"`
	AllowedRecipientMethods []CMPCKGRecipientMethod `json:"allowed_recipient_methods"`
}

// CMPControl is the shared tri-state control-gate shape used by ir's
// registration_token and authenticator_control. It stores ONLY a mode — no
// plaintext secret. Persisting the legacy plaintext answer (the
// CMPEnrollmentSettings.ExpectedAuthenticator anti-pattern) into the
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
// cross-certification (ccr) request may ask for. LIVE:
// validateCCRSubjectConstraints in dmsmanager_lwcmp.go rejects a ccr whose
// subject matches no AllowedDNPatterns entry, or whose dNSName SANs match no
// AllowedDNSSuffixes entry. An empty list imposes no constraint on that
// dimension (unlike CKG's allow-list, which is deny-all when empty).
type CMPSubjectConstraints struct {
	AllowedDNPatterns  []string `json:"allowed_dn_patterns"`
	AllowedDNSSuffixes []string `json:"allowed_dns_suffixes"`
}

// CMPTrustedRA scopes which RA certificates a self_and_trusted_ra rr trusts.
// Both fields are LIVE in validateTrustedRASigner (dmsmanager_lwcmp.go):
// RequireCMCRAEKU demands the id-kp-cmcRA EKU on the signer when set, and a
// non-empty ValidationCAIDs narrows chain validation to exactly those CAs.
// An empty ValidationCAIDs imposes no narrowing and falls back to the DMS-wide
// trustedRACAIDs boundary.
type CMPTrustedRA struct {
	ValidationCAIDs []string `json:"validation_ca_ids"`
	RequireCMCRAEKU bool     `json:"require_cmc_ra_eku"`
}

// ---------------------------------------------------------------------------
// Per-operation structs

// CMPIRSettings configures the Initialization Request (ir, RFC 9483 §4.1.1).
type CMPIRSettings struct {
	Enabled              bool                    `json:"enabled"`
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
// LIVE (all enforced in dmsmanager_lwcmp.go's shared enrollment path):
// RequireExistingDevice (rejects a cr from an unregistered device),
// CertificateBehavior (replace revokes the superseded certificate as part of
// issuance), MaximumActiveCertificates (caps how many non-revoked certificates
// a device may hold), AllowedProfileIDs (restricts the resolved issuance
// profile to this allow-list).
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
	Enabled           bool               `json:"enabled"`
	AllowedProfileIDs []string           `json:"allowed_profile_ids"`
	PolicyOverrides   CMPPolicyOverrides `json:"policy_overrides"`
}

// CMPKURSettings configures the Key Update Request (kur, RFC 9483 §4.1.3).
//
// This block holds only the per-operation kur concerns. The renewal policy
// proper — renewal window, expired-certificate allowance, additional validation
// CAs, revoke-superseded — lives on CMPSettings.ReEnrollmentSettings, which is
// where dmsmanager_lwcmp.go reads it from.
//
// LIVE fields:
//   - KeyPolicy (require_new_key rejects a kur that reuses the current public
//     key) and IdentityChangePolicy (forbid/san_only reject a subject/SAN
//     change), both enforced in dmsmanager_lwcmp.go
//   - PolicyOverrides.Workflow / .Confirmation, via the same shared
//     enrollment pipeline ir/cr/p10cr use (EffectiveWorkflow/
//     EffectiveAcceptImplicit below)
//
// NOT YET enforced: PolicyOverrides.IssuanceProfileID — the per-operation
// profile-override switch in dmsmanager_lwcmp.go only has cases for ir/cr/p10cr.
//
// Mandatory, non-configurable protocol invariants (documented, not fields):
// the cert being updated MUST protect the request (RFC 9483 §4.1.3); concurrent
// updates for the same cert are rejected; the old identity stays active until
// confirmation; an unconfirmed new cert is revoked on timeout.
type CMPKURSettings struct {
	Enabled              bool                    `json:"enabled"`
	KeyPolicy            CMPKeyPolicy            `json:"key_policy"`
	IdentityChangePolicy CMPIdentityChangePolicy `json:"identity_change_policy"`
	PolicyOverrides      CMPPolicyOverrides      `json:"policy_overrides"`
}

// CMPRRSettings configures Revocation Requests (rr, RFC 9483 §4.2).
//
// NOTE: an rr is ALWAYS signature-protected — that is a fixed RFC 9483 §5.3.2
// protocol invariant independent of the DMS auth_mode, so there is
// deliberately no "allow unprotected" option here.
//
// LIVE (all enforced in dmsmanager_lwcmp.go's LWCRevokeCertificate):
// Authorization (self_only forbids a trusted-RA revoking on another's
// behalf), AllowRevival (gates un-revoking a held certificate), AllowedReasons
// (rejects a revocation whose reason isn't in the list),
// TrustedRA.RequireCMCRAEKU. The one exception is TrustedRA.ValidationCAIDs —
// see its own doc comment.
//
// Revoking an already-expired certificate is never permitted: the CA service
// unconditionally rejects any status transition on a certificate whose status
// is StatusExpired (ca.go's UpdateCertificateStatus), so there is no
// per-DMS/RR setting for it.
type CMPRRSettings struct {
	Enabled        bool                       `json:"enabled"`
	Authorization  CMPRevocationAuthorization `json:"authorization"`
	AllowRevival   bool                       `json:"allow_revival"`
	AllowedReasons []CMPRevocationReason      `json:"allowed_reasons"`
	TrustedRA      CMPTrustedRA               `json:"trusted_ra"`
}

// CMPGENMInformationTypes gates the individual RFC 9483 §4.3 support messages a
// genm may ask for. The value defaults reflect what Lamassu actually answers
// today (verified in cmp_genmsg.go / dmsmanager_lwcmp.go):
//
//	LIVE (default true):
//	  CACertificates              → id-it-caCerts (LWCCACerts)
//	  SigningKeyTypes             → id-it-signKeyPairTypes (RSA+EC, static)
//	  EncryptionKeyTypes          → id-it-encKeyPairTypes (RSA, static)
//	  PreferredSymmetricAlgorithm → id-it-preferredSymmAlg (AES variant per CMPGENMSettings.PreferredSymmetricAlgorithm, default AES-256-CBC)
//	  SupportedLanguages          → id-it-supportedLangTags ("en", static)
//
//	LIVE (default false — operators opt in per DMS, since each depends on how
//	the DMS's CAs are set up rather than being a static capability):
//	  RootCAUpdate                → id-it-rootCaCert  (LWCGetRootCACertUpdate, real chain walk)
//	  CertificateRequestTemplate  → id-it-certReqTemplate (LWCGetCertReqTemplate, from the issuance profile)
//	  CurrentCRL                  → id-it-currentCRL  (LWCGetCRL via the VA client)
//	  CRLUpdate                   → id-it-crlStatusList (LWCGetCRL, honoring the request's CRLStatus)
//
//	ANSWERED BUT ALWAYS EMPTY:
//	  ProtocolEncryptionCertificate → id-it-caProtEncCert. Lamassu provisions no
//	  dedicated protocol-encryption certificate, so the genp carries the
//	  infoType with an ABSENT infoValue ("not available"), which is a valid
//	  answer — not a rejection.
//
// LIVE: genmInfoTypeEnabled in cmp_genmsg.go gates the handler on these
// booleans — a genm asking for a DISABLED info type is refused outright
// (notAuthorized). A type whose data provider legitimately has nothing to
// return (no VA client wired, no newer root than the EE's) answers
// with an RFC-compliant absent infoValue ("not available") instead of
// rejecting the request.
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
	// PreferredSymmetricAlgorithm is the AES variant advertised in the
	// id-it-preferredSymmAlg response when InformationTypes.PreferredSymmetricAlgorithm
	// is enabled. Empty defaults to AES-256-CBC (see resolveGENM).
	PreferredSymmetricAlgorithm CMPPreferredSymmetricAlgorithm `json:"preferred_symmetric_algorithm"`
}

// CMPCCRSettings configures Cross-Certification Requests (ccr, RFC 4210bis
// §5.3.11) — a privileged CA-to-CA operation, disabled by default.
//
// LIVE (enforced in cmp_crosscert.go / dmsmanager_lwcmp.go's
// LWCIssueCrossCertificate): Enabled (via operationEnabled in cmp.go),
// RequireCACertificate (signer must carry cA=TRUE), RequesterMode +
// TrustedRequesterCAIDs (Any is unrestricted regardless of the list;
// Restricted requires the signer to chain to a listed CA, and authorizes no
// one if the list is empty), RequireProofOfPossession, MaximumValidity (caps
// the issued cross-certificate's lifetime), SubjectConstraints (DN pattern /
// dNSName SAN allow-list), Workflow (administrator_approval defers issuance
// the same way ir/cr's phased workflow does).
//
// NOT YET enforced: IssuanceProfileID.
type CMPCCRSettings struct {
	Enabled                  bool                  `json:"enabled"`
	RequesterMode            CMPCCRRequesterMode   `json:"requester_mode"`
	TrustedRequesterCAIDs    []string              `json:"trusted_requester_ca_ids"`
	RequireCACertificate     bool                  `json:"require_ca_certificate"`
	RequireProofOfPossession bool                  `json:"require_proof_of_possession"`
	IssuanceProfileID        string                `json:"issuance_profile_id"`
	MaximumValidity          TimeDuration          `json:"maximum_validity"`
	SubjectConstraints       CMPSubjectConstraints `json:"subject_constraints"`
	Workflow                 CMPCCRWorkflow        `json:"workflow"`
}

// ---------------------------------------------------------------------------
// Per-operation policy resolution (LIVE)
//
// These resolvers apply an enrollment operation's policy_overrides on top of
// the DMS-general settings, and ARE consulted by the request handlers (see
// cmp_enrollment.go and cmp.go). Only the enrollment-initiating operations
// carry a workflow/confirmation override — ir, cr, p10cr and kur; every other
// operation string resolves to the DMS-general value.
//
// The issuance_profile_id override in CMPPolicyOverrides is resolved separately,
// at issuance time, by dmsmanager_lwcmp.go (resolveCMPIssuanceProfile).

// PolicyOverridesForOperation returns the CMPPolicyOverrides for a CMP
// enrollment operation ("ir"/"cr"/"p10cr"/"kur"). Any other operation yields
// the zero value ({inherit, inherit, nil}), so callers cleanly fall back to the
// DMS-general settings.
func (o *CMPEnrollmentSettings) PolicyOverridesForOperation(op string) CMPPolicyOverrides {
	switch op {
	case "ir":
		return o.IR.PolicyOverrides
	case "cr":
		return o.CR.PolicyOverrides
	case "p10cr":
		return o.P10CR.PolicyOverrides
	case "kur":
		return o.KUR.PolicyOverrides
	default:
		return CMPPolicyOverrides{}
	}
}

// EffectiveWorkflow resolves the transaction workflow (direct vs phased) for a
// CMP enrollment operation, applying policy_overrides.workflow on top of the
// DMS-general Workflow. "inherit" (or empty) defers to the general value.
func (o *CMPEnrollmentSettings) EffectiveWorkflow(op string) CMPWorkflow {
	switch o.PolicyOverridesForOperation(op).Workflow {
	case CMPInheritableWorkflowDirect:
		return CMPWorkflowDirect
	case CMPInheritableWorkflowPhased:
		return CMPWorkflowPhased
	default: // inherit / empty
		return o.Workflow
	}
}

// EffectiveAcceptImplicit resolves whether the server is willing to grant
// implicit confirmation for a CMP enrollment operation, applying
// policy_overrides.confirmation on top of the DMS-general AcceptImplicit.
// "implicit" forces willingness, "explicit" forces a certConf round-trip, and
// "inherit" (or empty) defers to the general value. Note this only expresses
// the server's willingness — implicit confirmation is granted only when the EE
// also requests it (id-it-implicitConfirm in generalInfo).
func (o *CMPEnrollmentSettings) EffectiveAcceptImplicit(op string) bool {
	switch o.PolicyOverridesForOperation(op).Confirmation {
	case CMPInheritableConfirmationImplicit:
		return true
	case CMPInheritableConfirmationExplicit:
		return false
	default: // inherit / empty
		return o.AcceptImplicit
	}
}
