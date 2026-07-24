package models

import "time"

// ResolveCMPSettings returns a copy of in with the nested CMP per-operation
// schema fully populated (defaults filled) and the two LIVE bridges resolved:
//
//   - CKG bridge: the DMS-general ServerKeyGenEnabled flag and the
//     IR/CR.CentralKeyGeneration.Enabled flags are unified into one effective
//     value (logical OR) and written back to all three, so the single shared
//     KGA gate in cmp_enrollment.go stays authoritative regardless of which
//     field an operator set.
//
//   - KUR bridge: the nested CMPKURSettings fields are reshaped 1:1 onto the
//     shared ReEnrollmentSettings (nested value wins when "set", otherwise the
//     existing ReEnrollmentSettings value is kept) and the resolved values are
//     written back into BOTH the nested KUR block and ReEnrollmentSettings, so
//     the existing re-enrollment enforcement (LWCReenroll window, expiry,
//     validation CAs, revoke-on-reenroll) honours them unchanged.
//
// The function is pure: it does not mutate in and returns a fully-populated
// value. It only acts when the DMS uses the CMP protocol; for any other
// protocol it returns in unchanged.
//
// NOTE ON THE KUR SHARED-FIELD COUPLING: ReEnrollmentSettings.ReEnrollmentDelta,
// EnableExpiredRenewal, AdditionalValidationCAs and RevokeOnReEnrollment are
// protocol-agnostic fields also consumed by EST re-enrollment and by
// certificate-expiry monitoring. Configuring them via the CMP kur block
// therefore also affects those paths. Decoupling per-protocol re-enrollment
// policy is deliberately out of scope (future work) — see RFC011.
func ResolveCMPSettings(in DMSSettings) DMSSettings {
	out := in
	if out.EnrollmentSettings.EnrollmentProtocol != CMP {
		return out
	}

	opts := out.EnrollmentSettings.EnrollmentOptionsLWCRFC9483
	rs := out.ReEnrollmentSettings

	// --- defaults ---------------------------------------------------------
	opts.IR = resolveIR(opts.IR)
	opts.CR = resolveCR(opts.CR)
	opts.P10CR = resolveP10CR(opts.P10CR)
	opts.KUR = resolveKUR(opts.KUR)
	opts.RR = resolveRR(opts.RR)
	opts.GENM = resolveGENM(opts.GENM)
	opts.CCR = resolveCCR(opts.CCR)

	// --- CKG bridge (one shared toggle, RFC011 Open Q1 option a) ----------
	ckgEffective := opts.ServerKeyGenEnabled ||
		opts.IR.CentralKeyGeneration.Enabled ||
		opts.CR.CentralKeyGeneration.Enabled
	opts.ServerKeyGenEnabled = ckgEffective
	opts.IR.CentralKeyGeneration.Enabled = ckgEffective
	opts.CR.CentralKeyGeneration.Enabled = ckgEffective

	// --- KUR bridge (reshape of the shared ReEnrollmentSettings) ----------
	// renewal_window ↔ ReEnrollmentDelta (non-zero nested wins).
	if opts.KUR.RenewalWindow != 0 {
		rs.ReEnrollmentDelta = opts.KUR.RenewalWindow
	} else {
		opts.KUR.RenewalWindow = rs.ReEnrollmentDelta
	}
	// allow_expired_certificate ↔ EnableExpiredRenewal (enable via either side).
	expiredEffective := opts.KUR.AllowExpiredCertificate || rs.EnableExpiredRenewal
	opts.KUR.AllowExpiredCertificate = expiredEffective
	rs.EnableExpiredRenewal = expiredEffective
	// additional_validation_ca_ids ↔ AdditionalValidationCAs (non-empty wins).
	if len(opts.KUR.AdditionalValidationCAIDs) > 0 {
		rs.AdditionalValidationCAs = append([]string(nil), opts.KUR.AdditionalValidationCAIDs...)
	} else {
		// Keep a non-nil slice on the nested side even when the source is empty.
		opts.KUR.AdditionalValidationCAIDs = append([]string{}, rs.AdditionalValidationCAs...)
	}
	// revoke_superseded_certificate ↔ RevokeOnReEnrollment (enable via either).
	revokeEffective := opts.KUR.RevokeSupersededCertificate || rs.RevokeOnReEnrollment
	opts.KUR.RevokeSupersededCertificate = revokeEffective
	rs.RevokeOnReEnrollment = revokeEffective

	out.EnrollmentSettings.EnrollmentOptionsLWCRFC9483 = opts
	out.ReEnrollmentSettings = rs
	return out
}

// --- per-operation defaulting ----------------------------------------------

func resolvePOPO(p CMPProofOfPossession) CMPProofOfPossession {
	if p.AllowedMethods == nil {
		// Default to the two POPO paths Lamassu actually recognizes today: the
		// inner CRMF self-signature, and RA-verified (raVerified) via a trusted
		// RA. challenge_response / encrypted_certificate are selectable in the
		// schema but not yet exercised.
		p.AllowedMethods = []CMPPOPOMethod{CMPPOPOMethodSignature, CMPPOPOMethodTrustedRA}
	}
	return p
}

func resolveCKG(c CMPCentralKeyGeneration) CMPCentralKeyGeneration {
	if c.AllowedRecipientMethods == nil {
		c.AllowedRecipientMethods = []CMPCKGRecipientMethod{
			CMPCKGRecipientMethodRSAKeyTransport,
			CMPCKGRecipientMethodECDHKeyAgreement,
		}
	}
	return c
}

func resolveControl(c CMPControl) CMPControl {
	if c.Mode == "" {
		c.Mode = CMPControlModeDisabled
	}
	return c
}

func resolveSubjectConstraints(s CMPSubjectConstraints) CMPSubjectConstraints {
	if s.AllowedDNPatterns == nil {
		s.AllowedDNPatterns = []string{}
	}
	if s.AllowedDNSSuffixes == nil {
		s.AllowedDNSSuffixes = []string{}
	}
	return s
}

func resolveTrustedRA(t CMPTrustedRA) CMPTrustedRA {
	if t.ValidationCAIDs == nil {
		t.ValidationCAIDs = []string{}
	}
	return t
}

func resolvePolicyOverrides(p CMPPolicyOverrides) CMPPolicyOverrides {
	if p.Workflow == "" {
		p.Workflow = CMPInheritableWorkflowInherit
	}
	if p.Confirmation == "" {
		p.Confirmation = CMPInheritableConfirmationInherit
	}
	return p
}

// Boolean defaults (Enabled, per-op flags, LIVE genm info-types) cannot be
// distinguished from an explicit false once deserialized, so they are applied
// only to a "fresh" (unconfigured) block. Freshness is detected per operation
// by observing that its mandatory enum field is still empty on input — a block
// that has ever round-tripped through resolution always carries a non-empty
// enum there, so an operator's explicit false is preserved thereafter.

func resolveIR(ir CMPIRSettings) CMPIRSettings {
	fresh := ir.RegistrationMode == ""
	if fresh {
		ir.RegistrationMode = CMPOpRegistrationModeInherit
		ir.Enabled = true
		ir.ProofOfPossession.Required = true
	}
	if ir.ExistingDevicePolicy == "" {
		ir.ExistingDevicePolicy = CMPExistingDevicePolicyReject
	}
	if ir.IdentitySource == "" {
		ir.IdentitySource = CMPIdentitySourceSubjectOrSAN
	}
	ir.ProofOfPossession = resolvePOPO(ir.ProofOfPossession)
	ir.RegistrationToken = resolveControl(ir.RegistrationToken)
	ir.AuthenticatorControl = resolveControl(ir.AuthenticatorControl)
	ir.CentralKeyGeneration = resolveCKG(ir.CentralKeyGeneration)
	ir.PolicyOverrides = resolvePolicyOverrides(ir.PolicyOverrides)
	return ir
}

func resolveCR(cr CMPCRSettings) CMPCRSettings {
	fresh := cr.CertificateBehavior == ""
	if fresh {
		cr.CertificateBehavior = CMPCertificateBehaviorAdditional
		cr.Enabled = true
		cr.RequireExistingDevice = true
		cr.MaximumActiveCertificates = 2
		cr.ProofOfPossession.Required = true
	}
	if cr.AllowedProfileIDs == nil {
		cr.AllowedProfileIDs = []string{}
	}
	cr.ProofOfPossession = resolvePOPO(cr.ProofOfPossession)
	cr.CentralKeyGeneration = resolveCKG(cr.CentralKeyGeneration)
	cr.PolicyOverrides = resolvePolicyOverrides(cr.PolicyOverrides)
	return cr
}

func resolveP10CR(p CMPP10CRSettings) CMPP10CRSettings {
	fresh := p.RegistrationMode == ""
	if fresh {
		p.RegistrationMode = CMPOpRegistrationModeInherit
		// p10cr is disabled by default (the product spec ships it off): only the
		// enum default is applied here, Enabled stays at its zero value (false).
	}
	if p.ExistingDevicePolicy == "" {
		p.ExistingDevicePolicy = CMPExistingDevicePolicyReject
	}
	if p.AllowedProfileIDs == nil {
		p.AllowedProfileIDs = []string{}
	}
	p.PolicyOverrides = resolvePolicyOverrides(p.PolicyOverrides)
	return p
}

func resolveKUR(k CMPKURSettings) CMPKURSettings {
	fresh := k.KeyPolicy == ""
	if fresh {
		k.KeyPolicy = CMPKeyPolicyRequireNew
		k.Enabled = true
	}
	if k.IdentityChangePolicy == "" {
		k.IdentityChangePolicy = CMPIdentityChangePolicyForbid
	}
	if k.AdditionalValidationCAIDs == nil {
		k.AdditionalValidationCAIDs = []string{}
	}
	k.PolicyOverrides = resolvePolicyOverrides(k.PolicyOverrides)
	return k
}

func resolveRR(rr CMPRRSettings) CMPRRSettings {
	fresh := rr.Authorization == ""
	if fresh {
		rr.Authorization = CMPRevocationAuthorizationSelfOnly
		rr.Enabled = true
		rr.AllowExpiredTarget = true
		rr.TrustedRA.RequireCMCRAEKU = true
		if rr.AllowedReasons == nil {
			rr.AllowedReasons = []CMPRevocationReason{
				CMPRevocationReasonUnspecified,
				CMPRevocationReasonKeyCompromise,
				CMPRevocationReasonCessationOfOperation,
				CMPRevocationReasonSuperseded,
			}
		}
	}
	if rr.AllowedReasons == nil {
		rr.AllowedReasons = []CMPRevocationReason{}
	}
	rr.TrustedRA = resolveTrustedRA(rr.TrustedRA)
	return rr
}

func resolveGENM(g CMPGENMSettings) CMPGENMSettings {
	fresh := g.AccessPolicy == ""
	if fresh {
		g.AccessPolicy = CMPGENMAccessPolicyPublicDiscovery
		g.Enabled = true
		// LIVE info types default on (they are always answered today); STUB
		// types stay off (their service methods return nil).
		g.InformationTypes.CACertificates = true
		g.InformationTypes.SigningKeyTypes = true
		g.InformationTypes.EncryptionKeyTypes = true
		g.InformationTypes.PreferredSymmetricAlgorithm = true
		g.InformationTypes.SupportedLanguages = true
	}
	return g
}

func resolveCCR(c CMPCCRSettings) CMPCCRSettings {
	fresh := c.Workflow == ""
	if fresh {
		// ccr is a privileged CA-to-CA operation, disabled by default — Enabled
		// stays false. The remaining safe defaults are applied on a fresh block.
		c.Workflow = CMPCCRWorkflowAdministratorApproval
		c.RequireCACertificate = true
		c.RequireProofOfPossession = true
		c.MaximumValidity = TimeDuration(8760 * time.Hour)
	}
	if c.TrustedRequesterCAIDs == nil {
		c.TrustedRequesterCAIDs = []string{}
	}
	c.SubjectConstraints = resolveSubjectConstraints(c.SubjectConstraints)
	return c
}
