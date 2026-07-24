package models

import "testing"

// optsWith builds an EnrollmentOptionsLWCRFC9483 with the given DMS-general
// workflow/acceptImplicit and an IR policy_overrides carrying wf/conf.
func optsWith(general CMPWorkflow, acceptImplicit bool, wf CMPInheritableWorkflow, conf CMPInheritableConfirmation) *EnrollmentOptionsLWCRFC9483 {
	o := &EnrollmentOptionsLWCRFC9483{
		Workflow:       general,
		AcceptImplicit: acceptImplicit,
	}
	o.IR.PolicyOverrides = CMPPolicyOverrides{Workflow: wf, Confirmation: conf}
	return o
}

func TestEffectiveWorkflow(t *testing.T) {
	tests := []struct {
		name     string
		general  CMPWorkflow
		override CMPInheritableWorkflow
		op       string
		want     CMPWorkflow
	}{
		{"inherit defers to general direct", CMPWorkflowDirect, CMPInheritableWorkflowInherit, "ir", CMPWorkflowDirect},
		{"inherit defers to general phased", CMPWorkflowPhased, CMPInheritableWorkflowInherit, "ir", CMPWorkflowPhased},
		{"empty override defers to general", CMPWorkflowPhased, "", "ir", CMPWorkflowPhased},
		{"override direct wins over general phased", CMPWorkflowPhased, CMPInheritableWorkflowDirect, "ir", CMPWorkflowDirect},
		{"override phased wins over general direct", CMPWorkflowDirect, CMPInheritableWorkflowPhased, "ir", CMPWorkflowPhased},
		{"non-enrollment op ignores overrides", CMPWorkflowPhased, CMPInheritableWorkflowDirect, "certConf", CMPWorkflowPhased},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := optsWith(tc.general, false, tc.override, CMPInheritableConfirmationInherit)
			if got := o.EffectiveWorkflow(tc.op); got != tc.want {
				t.Fatalf("EffectiveWorkflow(%q) = %q, want %q", tc.op, got, tc.want)
			}
		})
	}
}

func TestEffectiveAcceptImplicit(t *testing.T) {
	tests := []struct {
		name     string
		general  bool
		override CMPInheritableConfirmation
		op       string
		want     bool
	}{
		{"inherit defers to general true", true, CMPInheritableConfirmationInherit, "ir", true},
		{"inherit defers to general false", false, CMPInheritableConfirmationInherit, "ir", false},
		{"empty override defers to general", true, "", "ir", true},
		{"explicit forces false over general true", true, CMPInheritableConfirmationExplicit, "ir", false},
		{"implicit forces true over general false", false, CMPInheritableConfirmationImplicit, "ir", true},
		{"non-enrollment op ignores overrides", true, CMPInheritableConfirmationExplicit, "rr", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := optsWith(CMPWorkflowDirect, tc.general, CMPInheritableWorkflowInherit, tc.override)
			if got := o.EffectiveAcceptImplicit(tc.op); got != tc.want {
				t.Fatalf("EffectiveAcceptImplicit(%q) = %v, want %v", tc.op, got, tc.want)
			}
		})
	}
}

// TestPolicyOverridesForOperation confirms each enrollment op reads its own
// nested overrides and everything else gets the zero (all-inherit) value.
func TestPolicyOverridesForOperation(t *testing.T) {
	o := &EnrollmentOptionsLWCRFC9483{}
	o.IR.PolicyOverrides = CMPPolicyOverrides{Workflow: CMPInheritableWorkflowPhased}
	o.CR.PolicyOverrides = CMPPolicyOverrides{Confirmation: CMPInheritableConfirmationExplicit}
	o.P10CR.PolicyOverrides = CMPPolicyOverrides{Workflow: CMPInheritableWorkflowDirect}
	pid := "profile-123"
	o.KUR.PolicyOverrides = CMPPolicyOverrides{IssuanceProfileID: &pid}

	if o.PolicyOverridesForOperation("ir").Workflow != CMPInheritableWorkflowPhased {
		t.Errorf("ir overrides not returned")
	}
	if o.PolicyOverridesForOperation("cr").Confirmation != CMPInheritableConfirmationExplicit {
		t.Errorf("cr overrides not returned")
	}
	if o.PolicyOverridesForOperation("p10cr").Workflow != CMPInheritableWorkflowDirect {
		t.Errorf("p10cr overrides not returned")
	}
	if got := o.PolicyOverridesForOperation("kur").IssuanceProfileID; got == nil || *got != pid {
		t.Errorf("kur overrides not returned")
	}
	if got := o.PolicyOverridesForOperation("genm"); got != (CMPPolicyOverrides{}) {
		t.Errorf("non-enrollment op should return zero overrides, got %+v", got)
	}
}
