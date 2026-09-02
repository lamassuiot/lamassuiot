package cmp

import (
	"context"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCMPSettings_NestedRoundTrip proves the nested per-operation CMP schema
// (RFC011) persists through Create → Get and that the remaining LIVE bridge
// resolves on the way out:
//
//   - defaulting: a DMS created with only the flat/general CMP fields comes back
//     with every nested operation block fully populated (enum + Enabled
//     defaults), so partial rows project into the new shape.
//   - CKG bridge: the flat ServerKeyGenEnabled toggle is mirrored into
//     ir/cr.central_key_generation.enabled.
//   - re-enrollment independence: cmp_settings.reenrollment_settings is stored
//     and read back verbatim. It used to be reshaped from the nested kur block
//     (and vice versa); now each stands alone, so a create-time value must
//     survive untouched no matter what the kur block says.
func TestCMPSettings_NestedRoundTrip(t *testing.T) {
	f := newCMPTestFixture(t)
	ctx := context.Background()

	created, err := f.dmsMgr.Service.CreateDMS(ctx, services.CreateDMSInput{
		ID:   "cmp-dms-nested-roundtrip",
		Name: "CMP Nested Settings Round-Trip",
		Settings: models.DMSSettings{
			Protocol: models.CMP,
			CMP: &models.CMPSettings{
				EnrollmentSettings: models.CMPEnrollmentSettings{
					CommonEnrollmentSettings: models.CommonEnrollmentSettings{
						EnrollmentCA:     f.enrollCA.ID,
						RegistrationMode: models.PreRegistration,
						DeviceProvisionProfile: models.DeviceProvisionProfile{
							Icon:      "cmp",
							IconColor: "#004466",
							Metadata:  map[string]any{},
							Tags:      []string{"cmp"},
						},
					},
					AuthMode: models.CMPAuthModeClientCertificate,
					AuthOptionsMTLS: models.AuthOptionsClientCertificate{
						ValidationCAs: []string{f.enrollCA.ID},
					},
					EnforcePOPO: true,
					// Flat CKG toggle ON — must mirror into nested ir/cr CKG.
					ServerKeyGenEnabled: true,
					// Nested KUR block, marked non-fresh via KeyPolicy so its
					// explicit values survive resolution.
					KUR: models.CMPKURSettings{
						Enabled:              true,
						KeyPolicy:            models.CMPKeyPolicyRequireNew,
						IdentityChangePolicy: models.CMPIdentityChangePolicySANOnly,
					},
				},
				// The renewal policy is independent of the kur block above and
				// must round-trip exactly as written.
				ReEnrollmentSettings: models.CMPReEnrollmentSettings{
					CommonReEnrollmentSettings: models.CommonReEnrollmentSettings{
						AdditionalValidationCAs:     []string{"kur-extra-ca"},
						ReEnrollmentDelta:           models.TimeDuration(48 * time.Hour),
						EnableExpiredRenewal:        true,
						RevokeOnReEnrollment:        true,
						PreventiveReEnrollmentDelta: models.TimeDuration(3 * time.Minute),
						CriticalReEnrollmentDelta:   models.TimeDuration(2 * time.Minute),
					},
				},
				CADistributionSettings: models.CADistributionSettings{
					IncludeLamassuSystemCA: true,
					IncludeEnrollmentCA:    true,
				},
			},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, created)

	got, err := f.dmsMgr.Service.GetDMSByID(ctx, services.GetDMSByIDInput{ID: created.ID})
	require.NoError(t, err)

	opts := got.Settings.CMP.EnrollmentSettings

	// --- defaulting: nested blocks fully populated on read -----------------
	assert.True(t, opts.IR.Enabled, "fresh IR block must default Enabled=true")
	assert.True(t, opts.CR.RequireExistingDevice, "fresh CR block must default RequireExistingDevice=true")
	assert.Equal(t, models.CMPCertificateBehaviorAdditional, opts.CR.CertificateBehavior)
	assert.Equal(t, models.CMPRevocationAuthorizationSelfOnly, opts.RR.Authorization)
	assert.Equal(t, models.CMPGENMAccessPolicyPublicDiscovery, opts.GENM.AccessPolicy)
	assert.Equal(t, models.CMPCCRWorkflowAdministratorApproval, opts.CCR.Workflow)

	// --- CKG bridge: flat toggle mirrored into nested ir/cr ----------------
	assert.True(t, opts.ServerKeyGenEnabled, "flat ServerKeyGenEnabled must survive")
	assert.True(t, opts.IR.CentralKeyGeneration.Enabled, "CKG must mirror into IR")
	assert.True(t, opts.CR.CentralKeyGeneration.Enabled, "CKG must mirror into CR")

	// --- per-operation KUR fields survive ----------------------------------
	assert.Equal(t, models.CMPKeyPolicyRequireNew, opts.KUR.KeyPolicy,
		"KUR.KeyPolicy must round-trip unchanged")
	assert.Equal(t, models.CMPIdentityChangePolicySANOnly, opts.KUR.IdentityChangePolicy,
		"KUR.IdentityChangePolicy must round-trip unchanged")

	// --- re-enrollment policy round-trips verbatim -------------------------
	rs := got.Settings.CMP.ReEnrollmentSettings
	assert.Equal(t, models.TimeDuration(48*time.Hour), rs.ReEnrollmentDelta)
	assert.True(t, rs.EnableExpiredRenewal)
	assert.True(t, rs.RevokeOnReEnrollment)
	assert.Equal(t, []string{"kur-extra-ca"}, rs.AdditionalValidationCAs)
	assert.Equal(t, models.TimeDuration(3*time.Minute), rs.PreventiveReEnrollmentDelta)
	assert.Equal(t, models.TimeDuration(2*time.Minute), rs.CriticalReEnrollmentDelta)

	// The EST container must stay absent on a CMP DMS.
	assert.Nil(t, got.Settings.EST, "a CMP DMS must not carry est_settings")
}
