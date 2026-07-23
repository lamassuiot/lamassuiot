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
// (RFC011) persists through Create → Get and that the two LIVE bridges resolve
// on the way out:
//
//   - defaulting: a DMS created with only the flat/general CMP fields comes back
//     with every nested operation block fully populated (enum + Enabled
//     defaults), so legacy/partial rows project into the new shape.
//   - CKG bridge: the flat ServerKeyGenEnabled toggle is mirrored into
//     ir/cr.central_key_generation.enabled.
//   - KUR bridge: nested KUR fields (renewal_window, allow_expired_certificate,
//     revoke_superseded_certificate, additional_validation_ca_ids) reshape onto
//     the shared ReEnrollmentSettings that the live re-enrollment enforcement
//     already consumes, with the non-zero nested value winning over the
//     create-time ReEnrollmentSettings value.
func TestCMPSettings_NestedRoundTrip(t *testing.T) {
	f := newCMPTestFixture(t)
	ctx := context.Background()

	created, err := f.dmsMgr.Service.CreateDMS(ctx, services.CreateDMSInput{
		ID:   "cmp-dms-nested-roundtrip",
		Name: "CMP Nested Settings Round-Trip",
		Settings: models.DMSSettings{
			EnrollmentSettings: models.EnrollmentSettings{
				EnrollmentProtocol: models.CMP,
				EnrollmentCA:       f.enrollCA.ID,
				RegistrationMode:   models.PreRegistration,
				DeviceProvisionProfile: models.DeviceProvisionProfile{
					Icon:      "cmp",
					IconColor: "#004466",
					Metadata:  map[string]any{},
					Tags:      []string{"cmp"},
				},
				EnrollmentOptionsLWCRFC9483: models.EnrollmentOptionsLWCRFC9483{
					AuthMode: models.CMPAuthModeClientCertificate,
					AuthOptionsMTLS: models.AuthOptionsClientCertificate{
						ValidationCAs: []string{f.enrollCA.ID},
					},
					EnforcePOPO: true,
					// Flat CKG toggle ON — must mirror into nested ir/cr CKG.
					ServerKeyGenEnabled: true,
					// Nested KUR block, marked non-fresh via KeyPolicy so its
					// explicit values survive resolution and win the bridge.
					KUR: models.CMPKURSettings{
						Enabled:                     true,
						KeyPolicy:                   models.CMPKeyPolicyRequireNew,
						RenewalWindow:               models.TimeDuration(48 * time.Hour),
						AllowExpiredCertificate:     true,
						RevokeSupersededCertificate: true,
						AdditionalValidationCAIDs:   []string{"kur-extra-ca"},
					},
				},
			},
			// Create-time ReEnrollmentSettings deliberately DIFFER from the
			// nested KUR block so the round-trip proves the nested (non-zero)
			// values win the bridge rather than the other way round.
			ReEnrollmentSettings: models.ReEnrollmentSettings{
				AdditionalValidationCAs:     []string{},
				ReEnrollmentDelta:           models.TimeDuration(time.Hour),
				EnableExpiredRenewal:        false,
				RevokeOnReEnrollment:        false,
				PreventiveReEnrollmentDelta: models.TimeDuration(3 * time.Minute),
				CriticalReEnrollmentDelta:   models.TimeDuration(2 * time.Minute),
			},
			CADistributionSettings: models.CADistributionSettings{
				IncludeLamassuSystemCA: true,
				IncludeEnrollmentCA:    true,
			},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, created)

	got, err := f.dmsMgr.Service.GetDMSByID(ctx, services.GetDMSByIDInput{ID: created.ID})
	require.NoError(t, err)

	opts := got.Settings.EnrollmentSettings.EnrollmentOptionsLWCRFC9483

	// --- defaulting: nested blocks fully populated on read -----------------
	assert.Equal(t, models.CMPOpRegistrationModeInherit, opts.IR.RegistrationMode,
		"fresh IR block must default RegistrationMode to inherit")
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

	// --- KUR persisted-only field survives ---------------------------------
	assert.Equal(t, models.CMPKeyPolicyRequireNew, opts.KUR.KeyPolicy,
		"persisted-only KUR.KeyPolicy must round-trip unchanged")

	// --- KUR bridge: nested values reshaped onto ReEnrollmentSettings ------
	rs := got.Settings.ReEnrollmentSettings
	assert.Equal(t, models.TimeDuration(48*time.Hour), rs.ReEnrollmentDelta,
		"nested KUR.RenewalWindow must win over create-time ReEnrollmentDelta")
	assert.True(t, rs.EnableExpiredRenewal, "KUR.AllowExpiredCertificate must bridge to EnableExpiredRenewal")
	assert.True(t, rs.RevokeOnReEnrollment, "KUR.RevokeSupersededCertificate must bridge to RevokeOnReEnrollment")
	assert.Equal(t, []string{"kur-extra-ca"}, rs.AdditionalValidationCAs,
		"KUR.AdditionalValidationCAIDs must bridge to ReEnrollmentSettings.AdditionalValidationCAs")

	// --- KUR bridge is symmetric: resolved values also written back to KUR --
	assert.True(t, opts.KUR.AllowExpiredCertificate)
	assert.True(t, opts.KUR.RevokeSupersededCertificate)
	assert.Equal(t, models.TimeDuration(48*time.Hour), opts.KUR.RenewalWindow)
}
