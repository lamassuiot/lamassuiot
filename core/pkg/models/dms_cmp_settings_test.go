package models

import (
	"encoding/json"
	"slices"
	"testing"
	"time"
)

// newCMPSettings returns a minimal DMSSettings whose Protocol is CMP and whose
// nested/flat CMP fields are all zero — i.e. what an unconfigured row
// deserializes into before resolution.
func newCMPSettings() DMSSettings {
	return DMSSettings{
		Protocol: CMP,
		CMP:      &CMPSettings{},
	}
}

func TestResolveCMPSettings_NonCMPUntouched(t *testing.T) {
	in := DMSSettings{Protocol: EST, EST: &ESTSettings{}}
	out := ResolveCMPSettings(in)
	// An EST DMS must come back with no CMP container conjured up.
	if out.CMP != nil {
		t.Fatalf("expected non-CMP DMS to be left untouched, got CMP=%+v", out.CMP)
	}
	if out.EST == nil {
		t.Fatal("expected the EST container to survive resolution")
	}
}

func TestResolveCMPSettings_NilCMPContainerUntouched(t *testing.T) {
	// Protocol says CMP but the container is missing — resolution must not
	// panic dereferencing it; normalizeProtocolSettings is what allocates it.
	out := ResolveCMPSettings(DMSSettings{Protocol: CMP})
	if out.CMP != nil {
		t.Fatalf("expected nil CMP container to stay nil, got %+v", out.CMP)
	}
}

func TestResolveCMPSettings_FreshDefaults(t *testing.T) {
	out := ResolveCMPSettings(newCMPSettings())
	opts := out.CMP.EnrollmentSettings

	// Enum defaults.
	if opts.IR.IdentitySource != CMPIdentitySourceSubjectOrSAN {
		t.Errorf("IR.IdentitySource = %q, want subject_or_san", opts.IR.IdentitySource)
	}
	if !opts.IR.ProofOfPossession.Required {
		t.Error("IR.ProofOfPossession.Required = false, want true for fresh block")
	}
	if opts.CR.CertificateBehavior != CMPCertificateBehaviorAdditional {
		t.Errorf("CR.CertificateBehavior = %q, want additional", opts.CR.CertificateBehavior)
	}
	if !opts.CR.RequireExistingDevice {
		t.Error("CR.RequireExistingDevice = false, want true for fresh block")
	}
	if opts.CR.MaximumActiveCertificates != 2 {
		t.Errorf("CR.MaximumActiveCertificates = %d, want 2", opts.CR.MaximumActiveCertificates)
	}
	if opts.KUR.KeyPolicy != CMPKeyPolicyRequireNew {
		t.Errorf("KUR.KeyPolicy = %q, want require_new_key", opts.KUR.KeyPolicy)
	}
	if opts.KUR.IdentityChangePolicy != CMPIdentityChangePolicyForbid {
		t.Errorf("KUR.IdentityChangePolicy = %q, want forbid", opts.KUR.IdentityChangePolicy)
	}
	if opts.RR.Authorization != CMPRevocationAuthorizationSelfOnly {
		t.Errorf("RR.Authorization = %q, want self_only", opts.RR.Authorization)
	}
	if !opts.RR.TrustedRA.RequireCMCRAEKU {
		t.Error("RR.TrustedRA.RequireCMCRAEKU = false, want true for fresh block")
	}
	if opts.GENM.AccessPolicy != CMPGENMAccessPolicyPublicDiscovery {
		t.Errorf("GENM.AccessPolicy = %q, want public_discovery", opts.GENM.AccessPolicy)
	}
	if opts.CCR.Workflow != CMPCCRWorkflowAdministratorApproval {
		t.Errorf("CCR.Workflow = %q, want administrator_approval", opts.CCR.Workflow)
	}
	if !opts.CCR.RequireCACertificate || !opts.CCR.RequireProofOfPossession {
		t.Errorf("CCR require flags = %v/%v, want true/true", opts.CCR.RequireCACertificate, opts.CCR.RequireProofOfPossession)
	}
	if opts.CCR.MaximumValidity != TimeDuration(8760*time.Hour) {
		t.Errorf("CCR.MaximumValidity = %v, want 8760h", time.Duration(opts.CCR.MaximumValidity))
	}

	// Enabled defaults for a fresh block (ir/cr/kur/rr/genm on; p10cr/ccr off).
	for name, enabled := range map[string]bool{
		"IR": opts.IR.Enabled, "CR": opts.CR.Enabled,
		"KUR": opts.KUR.Enabled, "RR": opts.RR.Enabled, "GENM": opts.GENM.Enabled,
	} {
		if !enabled {
			t.Errorf("%s.Enabled = false, want true for fresh block", name)
		}
	}
	if opts.P10CR.Enabled {
		t.Error("P10CR.Enabled = true, want false (p10cr ships disabled)")
	}
	if opts.CCR.Enabled {
		t.Error("CCR.Enabled = true, want false (ccr ships disabled)")
	}

	// policy_overrides default to inherit/inherit/nil.
	po := opts.IR.PolicyOverrides
	if po.Workflow != CMPInheritableWorkflowInherit || po.Confirmation != CMPInheritableConfirmationInherit || po.IssuanceProfileID != nil {
		t.Errorf("IR.PolicyOverrides = %+v, want {inherit, inherit, nil}", po)
	}

	// Non-nil slices.
	if opts.IR.ProofOfPossession.AllowedMethods == nil {
		t.Error("IR.ProofOfPossession.AllowedMethods is nil, want non-nil default")
	}
	if opts.IR.CentralKeyGeneration.AllowedRecipientMethods == nil {
		t.Error("IR.CentralKeyGeneration.AllowedRecipientMethods is nil, want non-nil default")
	}
	if opts.CR.AllowedProfileIDs == nil || opts.P10CR.AllowedProfileIDs == nil {
		t.Error("CR/P10CR.AllowedProfileIDs is nil, want non-nil empty slice")
	}
	// Asserted by content rather than by count: a bare length check still passes
	// when the composition changes, and the composition is what matters.
	wantReasons := []CMPRevocationReason{
		CMPRevocationReasonUnspecified,
		CMPRevocationReasonKeyCompromise,
		CMPRevocationReasonCessationOfOperation,
		CMPRevocationReasonSuperseded,
	}
	if !slices.Equal(opts.RR.AllowedReasons, wantReasons) {
		t.Errorf("RR.AllowedReasons = %v, want %v", opts.RR.AllowedReasons, wantReasons)
	}
	if opts.CCR.TrustedRequesterCAIDs == nil || opts.CCR.SubjectConstraints.AllowedDNPatterns == nil || opts.CCR.SubjectConstraints.AllowedDNSSuffixes == nil {
		t.Error("CCR slices are nil, want non-nil empty slices")
	}
	if opts.CCR.RequesterMode != CMPCCRRequesterModeAny {
		t.Errorf("CCR.RequesterMode = %q, want %q (must default to unrestricted for backward compatibility)", opts.CCR.RequesterMode, CMPCCRRequesterModeAny)
	}

	// genm LIVE info types on, STUB off.
	it := opts.GENM.InformationTypes
	if !it.CACertificates || !it.SigningKeyTypes || !it.EncryptionKeyTypes ||
		!it.PreferredSymmetricAlgorithm || !it.SupportedLanguages {
		t.Errorf("genm LIVE info types not all enabled: %+v", it)
	}
	if it.RootCAUpdate || it.CertificateRequestTemplate || it.CurrentCRL ||
		it.CRLUpdate || it.ProtocolEncryptionCertificate {
		t.Errorf("genm STUB info types should default off: %+v", it)
	}
}

func TestResolveCMPSettings_CKGBridge(t *testing.T) {
	// (a) legacy flat toggle on → mirrored into ir/cr.
	in := newCMPSettings()
	in.CMP.EnrollmentSettings.ServerKeyGenEnabled = true
	out := ResolveCMPSettings(in)
	o := out.CMP.EnrollmentSettings
	if !o.ServerKeyGenEnabled || !o.IR.CentralKeyGeneration.Enabled || !o.CR.CentralKeyGeneration.Enabled {
		t.Errorf("CKG legacy→nested mirror failed: flat=%v ir=%v cr=%v",
			o.ServerKeyGenEnabled, o.IR.CentralKeyGeneration.Enabled, o.CR.CentralKeyGeneration.Enabled)
	}

	// (b) nested ir toggle on → mirrored back into the flat gate.
	in2 := newCMPSettings()
	in2.CMP.EnrollmentSettings.IR.CentralKeyGeneration.Enabled = true
	out2 := ResolveCMPSettings(in2)
	o2 := out2.CMP.EnrollmentSettings
	if !o2.ServerKeyGenEnabled || !o2.CR.CentralKeyGeneration.Enabled {
		t.Errorf("CKG nested→flat mirror failed: flat=%v cr=%v",
			o2.ServerKeyGenEnabled, o2.CR.CentralKeyGeneration.Enabled)
	}
}

func TestResolveCMPSettings_ReEnrollmentIsIndependent(t *testing.T) {
	// CMP renewal policy lives on its own ReEnrollmentSettings block and must
	// survive resolution verbatim. It used to be reshaped onto the kur block
	// (and vice versa) by a bridge; nothing may rewrite it now.
	in := newCMPSettings()
	in.CMP.ReEnrollmentSettings = CMPReEnrollmentSettings{
		CommonReEnrollmentSettings: CommonReEnrollmentSettings{
			ReEnrollmentDelta:       TimeDuration(48 * time.Hour),
			EnableExpiredRenewal:    true,
			AdditionalValidationCAs: []string{"ca-1", "ca-2"},
			RevokeOnReEnrollment:    true,
		},
	}
	in.CMP.EnrollmentSettings.KUR = CMPKURSettings{
		Enabled:   true,
		KeyPolicy: CMPKeyPolicyPermitReuse, // marks the block non-fresh
	}

	out := ResolveCMPSettings(in)
	rs := out.CMP.ReEnrollmentSettings

	if rs.ReEnrollmentDelta != TimeDuration(48*time.Hour) {
		t.Errorf("ReEnrollmentDelta = %v, want 48h preserved", time.Duration(rs.ReEnrollmentDelta))
	}
	if !rs.EnableExpiredRenewal {
		t.Error("EnableExpiredRenewal = false, want true preserved")
	}
	if !rs.RevokeOnReEnrollment {
		t.Error("RevokeOnReEnrollment = false, want true preserved")
	}
	if !slices.Equal(rs.AdditionalValidationCAs, []string{"ca-1", "ca-2"}) {
		t.Errorf("AdditionalValidationCAs = %v, want [ca-1 ca-2]", rs.AdditionalValidationCAs)
	}

	// The kur block keeps only its per-operation concerns, untouched.
	if kp := out.CMP.EnrollmentSettings.KUR.KeyPolicy; kp != CMPKeyPolicyPermitReuse {
		t.Errorf("KUR.KeyPolicy = %q, want permit_reuse preserved", kp)
	}
}

func TestResolveCMPSettings_ReEnrollmentSliceConcretized(t *testing.T) {
	out := ResolveCMPSettings(newCMPSettings())
	if out.CMP.ReEnrollmentSettings.AdditionalValidationCAs == nil {
		t.Error("ReEnrollmentSettings.AdditionalValidationCAs is nil, want non-nil empty slice")
	}
}

func TestResolveCMPSettings_PreservesExplicitFalse(t *testing.T) {
	// A block that has already round-tripped (enum set) must keep an explicit
	// Enabled=false rather than being re-defaulted to true.
	in := newCMPSettings()
	in.CMP.EnrollmentSettings.IR = CMPIRSettings{
		Enabled:        false,
		IdentitySource: CMPIdentitySourceSubjectOnly, // non-empty → not fresh
	}
	out := ResolveCMPSettings(in)
	if out.CMP.EnrollmentSettings.IR.Enabled {
		t.Error("IR.Enabled was re-defaulted to true; explicit false must be preserved")
	}
}

func TestResolveCMPSettings_Idempotent(t *testing.T) {
	once := ResolveCMPSettings(newCMPSettings())
	twice := ResolveCMPSettings(once)
	b1, _ := json.Marshal(once)
	b2, _ := json.Marshal(twice)
	if string(b1) != string(b2) {
		t.Errorf("resolution is not idempotent:\n once=%s\n twice=%s", b1, b2)
	}
}

func TestResolveCMPSettings_JSONRoundTrip(t *testing.T) {
	// A minimal CMP blob (no ir/cr/... keys) must deserialize into the
	// protocol-scoped shape and resolve without panic or loss of the general
	// fields. The common enrollment fields are embedded, so they sit flat
	// alongside the CMP-specific ones rather than under a nested object.
	raw := `{
		"protocol": "CMP_RFC9483",
		"cmp_settings": {
			"enrollment_settings": {
				"auth_mode": "CLIENT_CERTIFICATE",
				"enforce_popo": true,
				"server_key_gen_enabled": true,
				"workflow": "phased",
				"enrollment_ca": "enroll-ca",
				"registration_mode": "JITP"
			},
			"reenrollment_settings": {
				"reenrollment_delta": "24h0m0s",
				"revoke_on_reenrollment": true
			}
		}
	}`
	var s DMSSettings
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		t.Fatalf("blob failed to deserialize: %v", err)
	}
	if s.CMP == nil {
		t.Fatal("cmp_settings did not deserialize into the CMP container")
	}
	if s.EST != nil {
		t.Error("est_settings must stay nil for a CMP blob")
	}

	out := ResolveCMPSettings(s)
	o := out.CMP.EnrollmentSettings

	// CMP-specific general fields survive.
	if o.AuthMode != CMPAuthModeClientCertificate {
		t.Errorf("AuthMode lost: %q", o.AuthMode)
	}
	if !o.EnforcePOPO {
		t.Error("EnforcePOPO lost")
	}
	if o.Workflow != CMPWorkflowPhased {
		t.Errorf("Workflow lost: %q", o.Workflow)
	}
	// Embedded common fields survive alongside them.
	if o.EnrollmentCA != "enroll-ca" {
		t.Errorf("EnrollmentCA lost: %q", o.EnrollmentCA)
	}
	if o.RegistrationMode != JITP {
		t.Errorf("RegistrationMode lost: %q", o.RegistrationMode)
	}
	// CKG flag mirrored into the per-operation blocks.
	if !o.IR.CentralKeyGeneration.Enabled {
		t.Error("server_key_gen_enabled not mirrored into IR CKG")
	}
	// Re-enrollment policy is read straight from its own block.
	rs := out.CMP.ReEnrollmentSettings
	if rs.ReEnrollmentDelta != TimeDuration(24*time.Hour) {
		t.Errorf("ReEnrollmentDelta = %v, want 24h", time.Duration(rs.ReEnrollmentDelta))
	}
	if !rs.RevokeOnReEnrollment {
		t.Error("RevokeOnReEnrollment lost")
	}
}
