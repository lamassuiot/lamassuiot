package services

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"strconv"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/api/dto"
	authzmodels "github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/models"
	authzsdk "github.com/lamassuiot/lamassuiot/v4/connectors/authz/sdk"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Unit tests (no Docker) of the authz principal that follows an RA. The integration suite in
// assemblers/tests/dms-manager runs the same flows against the real authz, but Codecov only counts what runs here.

type dmsRepo struct {
	storage.DMSRepo
	dms                    map[string]*models.DMS
	failInsert, failUpdate bool
	failDelete             bool
}

func (r *dmsRepo) SelectExists(_ context.Context, id string) (bool, *models.DMS, error) {
	d, ok := r.dms[id]
	if !ok {
		return false, nil, nil
	}
	c := *d
	return true, &c, nil
}

func (r *dmsRepo) Insert(_ context.Context, d *models.DMS) (*models.DMS, error) {
	if r.failInsert {
		return nil, fmt.Errorf("insert failed")
	}
	r.dms[d.ID] = d
	return d, nil
}

func (r *dmsRepo) Update(_ context.Context, d *models.DMS) (*models.DMS, error) {
	if r.failUpdate {
		return nil, fmt.Errorf("update failed")
	}
	r.dms[d.ID] = d
	return d, nil
}

func (r *dmsRepo) Delete(_ context.Context, id string) error {
	if r.failDelete {
		return fmt.Errorf("delete failed")
	}
	delete(r.dms, id)
	return nil
}

type caStub struct {
	services.CAService
	cas map[string]*models.CACertificate
}

func (c caStub) GetCAByID(_ context.Context, in services.GetCAByIDInput) (*models.CACertificate, error) {
	if ca, ok := c.cas[in.CAID]; ok {
		return ca, nil
	}
	return nil, errs.ErrCANotFound
}

// authzStub keeps principals and grants in memory and fails like the real API: 404 for a missing principal, 500 for a duplicate.
type authzStub struct {
	authzsdk.PrincipalService
	principals map[string]*dto.PrincipalResponse
	grants     map[string][]dto.PrincipalPolicyResponse
	policies   map[string]bool
	failGrant  bool
	failDelete bool
	failGet    bool
	onGrant    func() // runs once, in the middle of the first grant, which then fails
}

func (a *authzStub) Get(_ context.Context, id string) (*dto.PrincipalResponse, error) {
	if a.failGet {
		return nil, &authzsdk.APIError{StatusCode: 503}
	}
	if p, ok := a.principals[id]; ok {
		read := *p // the real client decodes a new object on every read
		return &read, nil
	}
	return nil, &authzsdk.APIError{StatusCode: 404}
}

func (a *authzStub) Create(_ context.Context, req *dto.CreatePrincipalRequest) (*dto.PrincipalResponse, error) {
	if _, ok := a.principals[req.ID]; ok {
		return nil, &authzsdk.APIError{StatusCode: 500}
	}
	p := &dto.PrincipalResponse{ID: req.ID, Name: req.Name, Type: req.Type, AuthConfig: req.AuthConfig}
	a.principals[req.ID] = p
	return p, nil
}

func (a *authzStub) Update(_ context.Context, id string, req *dto.UpdatePrincipalRequest) (*dto.PrincipalResponse, error) {
	p := a.principals[id]
	p.Name = *req.Name
	if req.AuthConfig != nil {
		p.AuthConfig = req.AuthConfig
	}
	return p, nil
}

func (a *authzStub) Delete(_ context.Context, id string) error {
	if a.failDelete {
		return &authzsdk.APIError{StatusCode: 503}
	}
	delete(a.principals, id)
	delete(a.grants, id)
	return nil
}

// GetPolicies pages two grants at a time, with the bookmark being the offset of the next page.
func (a *authzStub) GetPolicies(_ context.Context, id string, query map[string]string) (*dto.ListPrincipalPoliciesResponse, error) {
	from, _ := strconv.Atoi(query["bookmark"])
	all, resp := a.grants[id], &dto.ListPrincipalPoliciesResponse{}
	resp.List = all[min(from, len(all)):min(from+2, len(all))]
	if from+2 < len(all) {
		resp.NextBookmark = strconv.Itoa(from + 2)
	}
	return resp, nil
}

func (a *authzStub) GrantPolicy(_ context.Context, id string, req *dto.GrantPolicyRequest) error {
	if hook := a.onGrant; hook != nil {
		a.onGrant = nil
		hook()
		return &authzsdk.APIError{StatusCode: 503}
	}
	if a.failGrant {
		return &authzsdk.APIError{StatusCode: 503}
	}
	for _, g := range a.grants[id] {
		if g.PolicyID == req.PolicyID {
			return &authzsdk.APIError{StatusCode: 500}
		}
	}
	a.grants[id] = append(a.grants[id], dto.PrincipalPolicyResponse{PolicyID: req.PolicyID, GrantedBy: req.GrantedBy})
	return nil
}

func (a *authzStub) RevokePolicy(_ context.Context, id, policyID string) error {
	a.grants[id] = withoutGrant(a.grants[id], policyID)
	return nil
}

func withoutGrant(grants []dto.PrincipalPolicyResponse, policyID string) []dto.PrincipalPolicyResponse {
	out := []dto.PrincipalPolicyResponse{}
	for _, g := range grants {
		if g.PolicyID != policyID {
			out = append(out, g)
		}
	}
	return out
}

type policyStub struct {
	authzsdk.PolicyService
	known map[string]bool
}

func (p policyStub) Get(_ context.Context, id string) (*dto.PolicyResponse, error) {
	if !p.known[id] {
		return nil, &authzsdk.APIError{StatusCode: 404}
	}
	return &dto.PolicyResponse{ID: id}, nil
}

type dmsAuthzEnv struct {
	svc           services.DMSManagerService
	repo          *dmsRepo
	authz         *authzStub
	ca1, ca2, ca3 *models.CACertificate
	cas           map[string]*models.CACertificate
}

func newDMSAuthzEnv(t *testing.T, withAuthz bool) *dmsAuthzEnv {
	t.Helper()
	newCA := func(id string) *models.CACertificate {
		key, err := chelpers.GenerateECDSAKey(elliptic.P256())
		require.NoError(t, err)
		crt, err := chelpers.GenerateSelfSignedCertificate(key, id)
		require.NoError(t, err)
		ca := &models.CACertificate{ID: id}
		ca.Certificate.Status = models.StatusActive
		ca.Certificate.Certificate = (*models.X509Certificate)(crt)
		return ca
	}
	env := &dmsAuthzEnv{
		repo:  &dmsRepo{dms: map[string]*models.DMS{}},
		authz: &authzStub{principals: map[string]*dto.PrincipalResponse{}, grants: map[string][]dto.PrincipalPolicyResponse{}, policies: map[string]bool{"policy-a": true, "policy-b": true}},
		ca1:   newCA("ca-1"),
		ca2:   newCA("ca-2"),
		ca3:   newCA("ca-3"),
	}
	env.cas = map[string]*models.CACertificate{"ca-1": env.ca1, "ca-2": env.ca2, "ca-3": env.ca3}
	builder := DMSManagerBuilder{
		Logger:     logrus.NewEntry(logrus.New()),
		DMSStorage: env.repo,
		CAClient:   caStub{cas: env.cas},
	}
	if withAuthz {
		builder.Authz = &authzsdk.Client{Principals: env.authz, Policies: policyStub{known: env.authz.policies}}
		builder.AuthzPrincipals = config.DMSAuthzPrincipals{Enabled: true, PolicyIDs: []string{"policy-a", "policy-b"}, SubjectAttributeMappings: map[string]string{"device_id": "x509.subject.cn"}}
	}
	env.svc = NewDMSManagerService(builder)
	return env
}

func dmsSettings(caID string, principal *bool) models.DMSSettings {
	var s models.DMSSettings
	s.EnrollmentSettings.EnrollmentCA = caID
	if principal != nil {
		s.AuthzPrincipalSettings = &models.AuthzPrincipalSettings{Enabled: *principal}
	}
	return s
}

func ptr[T any](v T) *T { return &v }

func (e *dmsAuthzEnv) create(id, caID string, principal bool) error {
	_, err := e.svc.CreateDMS(context.Background(), services.CreateDMSInput{ID: id, Name: "Field devices", Settings: dmsSettings(caID, &principal)})
	return err
}

func (e *dmsAuthzEnv) update(id string, s models.DMSSettings) error {
	_, err := e.svc.UpdateDMS(context.Background(), services.UpdateDMSInput{ID: id, Name: "Field devices", Settings: &s})
	return err
}

// trusts is the fingerprint the principal of an RA is pinned to.
func (e *dmsAuthzEnv) trusts(id string) any {
	return (*e.authz.principals["dms:"+id].AuthConfig)["ca_trust"].(map[string]any)["value"]
}

func (e *dmsAuthzEnv) grantedPolicies(id string) []string {
	var ids []string
	for _, g := range e.authz.grants["dms:"+id] {
		ids = append(ids, g.PolicyID)
	}
	return ids
}

func TestDMSAuthzPrincipalFollowsTheDMS(t *testing.T) {
	env, ctx := newDMSAuthzEnv(t, true), context.Background()

	require.NoError(t, env.create("ra-1", "ca-1", true))
	require.NoError(t, env.create("ra-2", "ca-1", false))
	assert.Equal(t, "x509", env.authz.principals["dms:ra-1"].Type)
	assert.Equal(t, "ra-1", managedDMS(env.authz.principals["dms:ra-1"].AuthConfig))
	assert.ElementsMatch(t, []string{"policy-a", "policy-b"}, env.grantedPolicies("ra-1"))
	assert.NotContains(t, env.authz.principals, "dms:ra-2", "an RA with the switch off gets no principal")

	before := env.trusts("ra-1")
	require.NoError(t, env.update("ra-1", dmsSettings("ca-2", ptr(true))))
	assert.NotEqual(t, before, env.trusts("ra-1"), "the principal follows a change of Enrollment CA")

	env.authz.grants["dms:ra-1"] = append(env.authz.grants["dms:ra-1"], dto.PrincipalPolicyResponse{PolicyID: "by-hand", GrantedBy: "admin"})
	require.NoError(t, env.update("ra-1", dmsSettings("ca-2", nil)))
	assert.Contains(t, env.authz.principals, "dms:ra-1", "an update that omits the switch keeps it")
	assert.Contains(t, env.grantedPolicies("ra-1"), "by-hand", "grants made by others are kept")

	require.NoError(t, env.update("ra-1", dmsSettings("ca-2", ptr(false))))
	assert.NotContains(t, env.authz.principals, "dms:ra-1", "turning the switch off deletes the principal")
	require.NoError(t, env.update("ra-1", dmsSettings("ca-2", ptr(true))))
	assert.Contains(t, env.authz.principals, "dms:ra-1")

	require.NoError(t, env.svc.DeleteDMS(ctx, services.DeleteDMSInput{ID: "ra-1"}))
	assert.NotContains(t, env.authz.principals, "dms:ra-1", "deleting the RA deletes the principal")
	require.NoError(t, env.svc.DeleteDMS(ctx, services.DeleteDMSInput{ID: "ra-2"}), "an RA without a principal deletes fine")
}

func TestDMSAuthzPrincipalIsOnlyKeptWhenTheFeatureIsOn(t *testing.T) {
	env := newDMSAuthzEnv(t, false)

	assert.ErrorIs(t, env.create("ra-1", "ca-1", true), errs.ErrValidateBadRequest)
	require.NoError(t, env.create("ra-2", "ca-1", false))
	assert.NoError(t, env.svc.DeleteDMS(context.Background(), services.DeleteDMSInput{ID: "ra-2"}))
}

func TestDMSAuthzPrincipalCreateFailureLeavesNothingBehind(t *testing.T) {
	cases := []struct {
		name    string
		id, ca  string
		prepare func(e *dmsAuthzEnv)
		wantErr error
	}{
		{name: "no Enrollment CA", id: "ra-1", ca: "", wantErr: errs.ErrValidateBadRequest},
		{name: "unknown Enrollment CA", id: "ra-1", ca: "nope", wantErr: errs.ErrValidateBadRequest},
		{name: "revoked Enrollment CA", id: "ra-1", ca: "ca-1", wantErr: errs.ErrValidateBadRequest, prepare: func(e *dmsAuthzEnv) { e.ca1.Certificate.Status = models.StatusRevoked }},
		{name: "id with a slash", id: "ra/x", ca: "ca-1", wantErr: errs.ErrValidateBadRequest},
		{name: "unknown policy", id: "ra-1", ca: "ca-1", prepare: func(e *dmsAuthzEnv) { delete(e.authz.policies, "policy-b") }},
		{name: "a grant fails after the principal is created", id: "ra-1", ca: "ca-1", prepare: func(e *dmsAuthzEnv) { e.authz.failGrant = true }},
		{name: "storing the RA fails", id: "ra-1", ca: "ca-1", prepare: func(e *dmsAuthzEnv) { e.repo.failInsert = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newDMSAuthzEnv(t, true)
			if tc.prepare != nil {
				tc.prepare(env)
			}

			err := env.create(tc.id, tc.ca, true)

			require.Error(t, err)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
			}
			assert.Empty(t, env.repo.dms, "the RA is not stored")
			assert.Empty(t, env.authz.principals, "no principal is left behind")
		})
	}

	t.Run("an x509 principal not managed for this RA is kept", func(t *testing.T) {
		env := newDMSAuthzEnv(t, true)
		config := &authzmodels.AuthConfig{"match_mode": "serial_and_ca"}
		env.authz.principals["dms:ra-1"] = &dto.PrincipalResponse{ID: "dms:ra-1", Type: "x509", AuthConfig: config}

		assert.ErrorIs(t, env.create("ra-1", "ca-1", true), errs.ErrValidateBadRequest)
		assert.Equal(t, config, env.authz.principals["dms:ra-1"].AuthConfig)
	})

	t.Run("principal of another type is kept", func(t *testing.T) {
		env := newDMSAuthzEnv(t, true)
		env.authz.principals["dms:ra-1"] = &dto.PrincipalResponse{ID: "dms:ra-1", Type: "oidc"}

		require.Error(t, env.create("ra-1", "ca-1", true))
		assert.Equal(t, "oidc", env.authz.principals["dms:ra-1"].Type)
	})
}

func TestDMSAuthzPrincipalFailedUpdateRestoresThePrincipal(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(e *dmsAuthzEnv)
	}{
		{name: "storing the RA fails", prepare: func(e *dmsAuthzEnv) { e.repo.failUpdate = true }},
		{name: "a grant fails", prepare: func(e *dmsAuthzEnv) {
			e.authz.grants["dms:ra-1"] = e.authz.grants["dms:ra-1"][:1]
			e.authz.failGrant = true
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newDMSAuthzEnv(t, true)
			require.NoError(t, env.create("ra-1", "ca-1", true))
			tc.prepare(env)
			before := env.authz.principals["dms:ra-1"].AuthConfig

			require.Error(t, env.update("ra-1", dmsSettings("ca-2", ptr(true))))

			assert.Equal(t, before, env.authz.principals["dms:ra-1"].AuthConfig, "the principal does not trust the CA that was never saved")
			assert.Equal(t, "ca-1", env.repo.dms["ra-1"].Settings.EnrollmentSettings.EnrollmentCA)
		})
	}
}

func TestDMSAuthzPrincipalRestoreDoesNotOverwriteANewerUpdate(t *testing.T) {
	cases := []struct {
		name     string
		newerCA  string
		failRead bool // the first request can not read the principal back
	}{
		{name: "another CA", newerCA: "ca-3"},
		{name: "the same CA", newerCA: "ca-2"},
		{name: "another CA and a failed read", newerCA: "ca-3", failRead: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newDMSAuthzEnv(t, true)
			require.NoError(t, env.create("ra-1", "ca-1", true))
			env.authz.grants["dms:ra-1"] = env.authz.grants["dms:ra-1"][:1]
			// While the first update grants the missing policy, the second one saves. Then the first one fails.
			env.authz.onGrant = func() {
				require.NoError(t, env.update("ra-1", dmsSettings(tc.newerCA, ptr(true))))
				env.authz.failGet = tc.failRead
			}

			require.Error(t, env.update("ra-1", dmsSettings("ca-2", ptr(true))))

			env.authz.failGet = false
			saved := env.repo.dms["ra-1"].Settings.EnrollmentSettings.EnrollmentCA
			assert.Equal(t, tc.newerCA, saved, "the newer update was saved")
			cfg := dmsPrincipalAuthConfig((*x509.Certificate)(env.cas[saved].Certificate.Certificate), nil)
			assert.Equal(t, cfg["ca_trust"].(map[string]any)["value"], env.trusts("ra-1"), "the principal trusts the CA that was saved")
		})
	}
}

func TestDMSAuthzPrincipalIsRecreatedWhenSavingFailsAfterDeletingIt(t *testing.T) {
	cases := map[string]func(e *dmsAuthzEnv) error{
		"deleting the RA": func(e *dmsAuthzEnv) error {
			e.repo.failDelete = true
			return e.svc.DeleteDMS(context.Background(), services.DeleteDMSInput{ID: "ra-1"})
		},
		"turning the switch off": func(e *dmsAuthzEnv) error {
			e.repo.failUpdate = true
			return e.update("ra-1", dmsSettings("ca-1", ptr(false)))
		},
	}
	for name, fail := range cases {
		t.Run(name, func(t *testing.T) {
			env := newDMSAuthzEnv(t, true)
			require.NoError(t, env.create("ra-1", "ca-1", true))
			before := env.trusts("ra-1")

			require.Error(t, fail(env))

			require.Contains(t, env.authz.principals, "dms:ra-1", "the stored RA still has the switch on, so its principal is back")
			assert.Equal(t, before, env.trusts("ra-1"))
			assert.ElementsMatch(t, []string{"policy-a", "policy-b"}, env.grantedPolicies("ra-1"))
		})
	}
}

func TestDMSAuthzPrincipalDeleteFailsWhenAuthzFails(t *testing.T) {
	env := newDMSAuthzEnv(t, true)
	require.NoError(t, env.create("ra-1", "ca-1", true))
	env.authz.failDelete = true

	require.Error(t, env.svc.DeleteDMS(context.Background(), services.DeleteDMSInput{ID: "ra-1"}))

	assert.Contains(t, env.repo.dms, "ra-1", "the RA is kept")
	assert.Contains(t, env.authz.principals, "dms:ra-1", "and so is its principal")
}

func TestDMSAuthzPrincipalSyncReadsEveryGrantPage(t *testing.T) {
	env := newDMSAuthzEnv(t, true)
	require.NoError(t, env.create("ra-1", "ca-1", true))
	grants := []dto.PrincipalPolicyResponse{}
	for i := range 5 {
		grants = append(grants, dto.PrincipalPolicyResponse{PolicyID: fmt.Sprintf("obsolete-%d", i), GrantedBy: models.DMSManagerSource})
	}
	env.authz.grants["dms:ra-1"] = append(grants, env.authz.grants["dms:ra-1"]...)

	require.NoError(t, env.update("ra-1", dmsSettings("ca-1", ptr(true))), "a wanted policy on a later page is not granted again")

	assert.ElementsMatch(t, []string{"policy-a", "policy-b"}, env.grantedPolicies("ra-1"), "obsolete grants on every page are revoked")
}

func TestDMSAuthzPrincipalAuthConfigPinsTheCA(t *testing.T) {
	crt := (*x509.Certificate)(newDMSAuthzEnv(t, true).ca1.Certificate.Certificate)

	cfg := dmsPrincipalAuthConfig(crt, map[string]string{"device_id": "x509.subject.cn"})

	assert.Equal(t, "any_from_ca", cfg["match_mode"])
	assert.Equal(t, map[string]any{"device_id": "x509.subject.cn"}, cfg["subject_attribute_mappings"])
	assert.Contains(t, cfg["ca_trust"].(map[string]any)["value"], "SHA256:")
	assert.NotContains(t, dmsPrincipalAuthConfig(crt, nil), "subject_attribute_mappings")
}
