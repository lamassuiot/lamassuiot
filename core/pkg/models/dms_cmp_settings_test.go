package models

import (
	"encoding/json"
	"testing"
	"time"
)

// newCMPSettings returns a minimal DMSSettings whose EnrollmentProtocol is CMP
// and whose nested/flat CMP fields are all zero — i.e. what a legacy (flat)
// row deserializes into before resolution.
func newCMPSettings() DMSSettings {
	return DMSSettings{
		EnrollmentSettings: EnrollmentSettings{
			EnrollmentProtocol: CMP,
		},
	}
}

func TestResolveCMPSettings_NonCMPUntouched(t *testing.T) {
	in := DMSSettings{
		EnrollmentSettings: EnrollmentSettings{EnrollmentProtocol: EST},
	}
	out := ResolveCMPSettings(in)
	// The nested CMP structs must remain zero for a non-CMP DMS.
	if out.EnrollmentSettings.EnrollmentOptionsLWCRFC9483.IR.RegistrationMode != "" {
		t.Fatalf("expected non-CMP DMS to be left untouched, got IR=%+v",
			out.EnrollmentSettings.EnrollmentOptionsLWCRFC9483.IR)
	}
}

func TestResolveCMPSettings_FreshDefaults(t *testing.T) {
	out := ResolveCMPSettings(newCMPSettings())
	opts := out.EnrollmentSettings.EnrollmentOptionsLWCRFC9483

	// Enum defaults.
	if opts.IR.RegistrationMode != CMPOpRegistrationModeInherit {
		t.Errorf("IR.RegistrationMode = %q, want inherit", opts.IR.RegistrationMode)
	}
	if opts.IR.ExistingDevicePolicy != CMPExistingDevicePolicyReject {
		t.Errorf("IR.ExistingDevicePolicy = %q, want reject", opts.IR.ExistingDevicePolicy)
	}
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
	if !opts.RR.AllowExpiredTarget {
		t.Error("RR.AllowExpiredTarget = false, want true for fresh block")
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
	if opts.RR.AllowedReasons == nil || len(opts.RR.AllowedReasons) != 4 {
		t.Errorf("RR.AllowedReasons = %v, want the 4 default reasons", opts.RR.AllowedReasons)
	}
	if opts.KUR.AdditionalValidationCAIDs == nil {
		t.Error("KUR.AdditionalValidationCAIDs is nil, want non-nil empty slice")
	}
	if opts.CCR.TrustedRequesterCAIDs == nil || opts.CCR.SubjectConstraints.AllowedDNPatterns == nil || opts.CCR.SubjectConstraints.AllowedDNSSuffixes == nil {
		t.Error("CCR slices are nil, want non-nil empty slices")
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
	in.EnrollmentSettings.EnrollmentOptionsLWCRFC9483.ServerKeyGenEnabled = true
	out := ResolveCMPSettings(in)
	o := out.EnrollmentSettings.EnrollmentOptionsLWCRFC9483
	if !o.ServerKeyGenEnabled || !o.IR.CentralKeyGeneration.Enabled || !o.CR.CentralKeyGeneration.Enabled {
		t.Errorf("CKG legacy→nested mirror failed: flat=%v ir=%v cr=%v",
			o.ServerKeyGenEnabled, o.IR.CentralKeyGeneration.Enabled, o.CR.CentralKeyGeneration.Enabled)
	}

	// (b) nested ir toggle on → mirrored back into the flat gate.
	in2 := newCMPSettings()
	in2.EnrollmentSettings.EnrollmentOptionsLWCRFC9483.IR.CentralKeyGeneration.Enabled = true
	out2 := ResolveCMPSettings(in2)
	o2 := out2.EnrollmentSettings.EnrollmentOptionsLWCRFC9483
	if !o2.ServerKeyGenEnabled || !o2.CR.CentralKeyGeneration.Enabled {
		t.Errorf("CKG nested→flat mirror failed: flat=%v cr=%v",
			o2.ServerKeyGenEnabled, o2.CR.CentralKeyGeneration.Enabled)
	}
}

func TestResolveCMPSettings_KURBridge_FromReEnrollment(t *testing.T) {
	// Legacy row: only ReEnrollmentSettings populated, nested KUR empty.
	in := newCMPSettings()
	in.ReEnrollmentSettings = ReEnrollmentSettings{
		ReEnrollmentDelta:       TimeDuration(48 * time.Hour),
		EnableExpiredRenewal:    true,
		AdditionalValidationCAs: []string{"ca-1", "ca-2"},
		RevokeOnReEnrollment:    true,
	}
	out := ResolveCMPSettings(in)
	kur := out.EnrollmentSettings.EnrollmentOptionsLWCRFC9483.KUR

	if kur.RenewalWindow != TimeDuration(48*time.Hour) {
		t.Errorf("KUR.RenewalWindow = %v, want 48h from ReEnrollmentDelta", time.Duration(kur.RenewalWindow))
	}
	if !kur.AllowExpiredCertificate {
		t.Error("KUR.AllowExpiredCertificate = false, want true from EnableExpiredRenewal")
	}
	if !kur.RevokeSupersededCertificate {
		t.Error("KUR.RevokeSupersededCertificate = false, want true from RevokeOnReEnrollment")
	}
	if len(kur.AdditionalValidationCAIDs) != 2 {
		t.Errorf("KUR.AdditionalValidationCAIDs = %v, want [ca-1 ca-2]", kur.AdditionalValidationCAIDs)
	}
}

func TestResolveCMPSettings_KURBridge_ToReEnrollment(t *testing.T) {
	// New-shape row: nested KUR populated, ReEnrollmentSettings empty → values
	// must be written back into ReEnrollmentSettings so live enforcement honours them.
	in := newCMPSettings()
	in.EnrollmentSettings.EnrollmentOptionsLWCRFC9483.KUR = CMPKURSettings{
		Enabled:                     true,
		RenewalWindow:               TimeDuration(12 * time.Hour),
		AllowExpiredCertificate:     true,
		AdditionalValidationCAIDs:   []string{"reenroll-ca"},
		RevokeSupersededCertificate: true,
		KeyPolicy:                   CMPKeyPolicyRequireNew, // marks the block non-fresh
	}
	out := ResolveCMPSettings(in)
	rs := out.ReEnrollmentSettings

	if rs.ReEnrollmentDelta != TimeDuration(12*time.Hour) {
		t.Errorf("ReEnrollmentDelta = %v, want 12h from KUR.RenewalWindow", time.Duration(rs.ReEnrollmentDelta))
	}
	if !rs.EnableExpiredRenewal {
		t.Error("EnableExpiredRenewal = false, want true from KUR")
	}
	if !rs.RevokeOnReEnrollment {
		t.Error("RevokeOnReEnrollment = false, want true from KUR")
	}
	if len(rs.AdditionalValidationCAs) != 1 || rs.AdditionalValidationCAs[0] != "reenroll-ca" {
		t.Errorf("AdditionalValidationCAs = %v, want [reenroll-ca]", rs.AdditionalValidationCAs)
	}
	// KeyPolicy (persisted-only) must survive.
	if out.EnrollmentSettings.EnrollmentOptionsLWCRFC9483.KUR.KeyPolicy != CMPKeyPolicyRequireNew {
		t.Errorf("KUR.KeyPolicy = %q, want require_new_key preserved", out.EnrollmentSettings.EnrollmentOptionsLWCRFC9483.KUR.KeyPolicy)
	}
}

func TestResolveCMPSettings_PreservesExplicitFalse(t *testing.T) {
	// A block that has already round-tripped (enum set) must keep an explicit
	// Enabled=false rather than being re-defaulted to true.
	in := newCMPSettings()
	in.EnrollmentSettings.EnrollmentOptionsLWCRFC9483.IR = CMPIRSettings{
		Enabled:          false,
		RegistrationMode: CMPOpRegistrationModeJITP, // non-empty → not fresh
	}
	out := ResolveCMPSettings(in)
	if out.EnrollmentSettings.EnrollmentOptionsLWCRFC9483.IR.Enabled {
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

func TestResolveCMPSettings_LegacyJSONRoundTrip(t *testing.T) {
	// A serialized legacy flat CMP blob (no ir/cr/... keys) must deserialize and
	// resolve without panic or data loss of the flat general fields.
	legacy := `{
		"enrollment_settings": {
			"protocol": "CMP_RFC9483",
			"lwc_rfc9483_settings": {
				"auth_mode": "CLIENT_CERTIFICATE",
				"enforce_popo": true,
				"server_key_gen_enabled": true,
				"workflow": "phased"
			}
		},
		"reenrollment_settings": {
			"reenrollment_delta": "24h0m0s",
			"revoke_on_reenrollment": true
		}
	}`
	var s DMSSettings
	if err := json.Unmarshal([]byte(legacy), &s); err != nil {
		t.Fatalf("legacy blob failed to deserialize: %v", err)
	}
	out := ResolveCMPSettings(s)
	o := out.EnrollmentSettings.EnrollmentOptionsLWCRFC9483

	// Flat general fields survive.
	if o.AuthMode != CMPAuthModeClientCertificate {
		t.Errorf("AuthMode lost: %q", o.AuthMode)
	}
	if !o.EnforcePOPO {
		t.Error("EnforcePOPO lost")
	}
	if o.Workflow != CMPWorkflowPhased {
		t.Errorf("Workflow lost: %q", o.Workflow)
	}
	// CKG legacy flag mirrored.
	if !o.IR.CentralKeyGeneration.Enabled {
		t.Error("legacy server_key_gen_enabled not mirrored into IR CKG")
	}
	// KUR bridge picked up the legacy re-enrollment values.
	if o.KUR.RenewalWindow != TimeDuration(24*time.Hour) {
		t.Errorf("KUR.RenewalWindow = %v, want 24h from legacy ReEnrollmentDelta", time.Duration(o.KUR.RenewalWindow))
	}
	if !o.KUR.RevokeSupersededCertificate {
		t.Error("KUR.RevokeSupersededCertificate not bridged from legacy revoke_on_reenrollment")
	}
}
