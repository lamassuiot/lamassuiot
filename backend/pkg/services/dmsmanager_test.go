package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/api/dto"
	authzmodels "github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/models"
	authzsdk "github.com/lamassuiot/lamassuiot/v4/connectors/authz/sdk"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
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
	grantsLeft *int // when set, grants fail once it reaches zero
	failDelete bool
	failGet    bool
	hang       bool   // Get waits for its context to end
	onGrant    func() // runs once, in the middle of the first grant, which then fails
}

func (a *authzStub) Get(ctx context.Context, id string) (*dto.PrincipalResponse, error) {
	if a.hang {
		<-ctx.Done()
		return nil, ctx.Err()
	}
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
	if a.failGrant || (a.grantsLeft != nil && *a.grantsLeft == 0) {
		return &authzsdk.APIError{StatusCode: 503}
	}
	if a.grantsLeft != nil {
		*a.grantsLeft--
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
	err   *error // when set, every lookup fails with it
}

func (p policyStub) Get(_ context.Context, id string) (*dto.PolicyResponse, error) {
	if p.err != nil && *p.err != nil {
		return nil, *p.err
	}
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
	keys          map[string]*ecdsa.PrivateKey
	logs          *logtest.Hook
	policyErr     error           // makes every policy lookup fail
	ctx           context.Context // of a caller allowed to grant policies, unless a test says otherwise
}

func grantCheck(allowed bool, calls *int) services.PolicyGrantCheck {
	return func(context.Context) (bool, error) {
		*calls++
		return allowed, nil
	}
}

func newDMSAuthzEnv(t *testing.T, withAuthz bool) *dmsAuthzEnv {
	t.Helper()
	keys := map[string]*ecdsa.PrivateKey{}
	newCA := func(id string) *models.CACertificate {
		key, err := chelpers.GenerateECDSAKey(elliptic.P256())
		require.NoError(t, err)
		crt, err := chelpers.GenerateSelfSignedCertificate(key, id)
		require.NoError(t, err)
		keys[id] = key
		ca := &models.CACertificate{ID: id}
		ca.Certificate.Status = models.StatusActive
		ca.Certificate.Certificate = (*models.X509Certificate)(crt)
		return ca
	}
	logger, logs := logtest.NewNullLogger()
	env := &dmsAuthzEnv{
		keys:  keys,
		logs:  logs,
		repo:  &dmsRepo{dms: map[string]*models.DMS{}},
		authz: &authzStub{principals: map[string]*dto.PrincipalResponse{}, grants: map[string][]dto.PrincipalPolicyResponse{}, policies: map[string]bool{"policy-a": true, "policy-b": true}},
		ca1:   newCA("ca-1"),
		ca2:   newCA("ca-2"),
		ca3:   newCA("ca-3"),
		ctx:   services.WithPolicyGrantCheck(context.Background(), grantCheck(true, new(int))),
	}
	env.cas = map[string]*models.CACertificate{"ca-1": env.ca1, "ca-2": env.ca2, "ca-3": env.ca3}
	builder := DMSManagerBuilder{
		Logger:     logrus.NewEntry(logger),
		DMSStorage: env.repo,
		CAClient:   caStub{cas: env.cas},
	}
	if withAuthz {
		builder.Authz = &authzsdk.Client{Principals: env.authz, Policies: policyStub{known: env.authz.policies, err: &env.policyErr}}
	}
	env.svc = NewDMSManagerService(builder)
	return env
}

// dmsSettings asks for a principal holding policy-a and policy-b, with device_id taken from the CN.
func dmsSettings(caID string, principal *bool) models.DMSSettings {
	var s models.DMSSettings
	s.EnrollmentSettings.EnrollmentCA = caID
	if principal != nil {
		s.AuthzPrincipalSettings = &models.AuthzPrincipalSettings{
			Enabled:                  *principal,
			PolicyIDs:                []string{"policy-a", "policy-b"},
			SubjectAttributeMappings: map[string]string{"device_id": "x509.subject.cn"},
		}
	}
	return s
}

func principalSettings(caID string, policyIDs []string, mappings map[string]string) models.DMSSettings {
	s := dmsSettings(caID, ptr(true))
	s.AuthzPrincipalSettings.PolicyIDs = policyIDs
	s.AuthzPrincipalSettings.SubjectAttributeMappings = mappings
	return s
}

func ptr[T any](v T) *T { return &v }

func (e *dmsAuthzEnv) create(id, caID string, principal bool) error {
	_, err := e.svc.CreateDMS(e.ctx, services.CreateDMSInput{ID: id, Name: "Field devices", Settings: dmsSettings(caID, &principal)})
	return err
}

func (e *dmsAuthzEnv) update(id string, s models.DMSSettings) error {
	_, err := e.svc.UpdateDMS(e.ctx, services.UpdateDMSInput{ID: id, Name: "Field devices", Settings: &s})
	return err
}

// trusts is the fingerprint the principal of an RA is pinned to.
func (e *dmsAuthzEnv) trusts(id string) any {
	return (*e.authz.principals["dms:"+id].AuthConfig)["ca_trust"].(map[string]any)["value"]
}

// snapshot is the principal, the grants and the stored RA, by value: a later change shows as a difference.
func (e *dmsAuthzEnv) snapshot(t *testing.T, id string) string {
	t.Helper()
	raw, err := json.Marshal([]any{e.authz.principals["dms:"+id], e.authz.grants["dms:"+id], e.repo.dms[id]})
	require.NoError(t, err)
	return string(raw)
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

func TestDMSAuthzPrincipalTakesPoliciesAndMappingsFromTheRA(t *testing.T) {
	env := newDMSAuthzEnv(t, true)
	mappings := func(id string) any {
		return (*env.authz.principals["dms:"+id].AuthConfig)["subject_attribute_mappings"]
	}

	_, err := env.svc.CreateDMS(env.ctx, services.CreateDMSInput{ID: "ra-1", Name: "Field devices", Settings: principalSettings("ca-1", []string{"policy-a"}, map[string]string{"client_id": "x509.serial_number"})})
	require.NoError(t, err)
	assert.Equal(t, []string{"policy-a"}, env.grantedPolicies("ra-1"))
	assert.Equal(t, map[string]any{"client_id": "x509.serial_number"}, mappings("ra-1"))

	require.NoError(t, env.update("ra-1", principalSettings("ca-1", []string{"policy-b", "policy-b"}, nil)), "a repeated id is granted once")
	assert.Equal(t, []string{"policy-b"}, env.grantedPolicies("ra-1"), "policies taken out of the RA are revoked")
	assert.Nil(t, mappings("ra-1"))
	assert.Equal(t, []string{"policy-b"}, env.repo.dms["ra-1"].Settings.AuthzPrincipalSettings.PolicyIDs)

	require.NoError(t, env.update("ra-1", principalSettings("ca-1", nil, nil)), "a principal without policies is allowed")
	assert.Contains(t, env.authz.principals, "dms:ra-1")
	assert.Empty(t, env.grantedPolicies("ra-1"))
}

func TestDMSAuthzPrincipalRejectsAnUnsupportedMapping(t *testing.T) {
	env := newDMSAuthzEnv(t, true)

	_, err := env.svc.CreateDMS(context.Background(), services.CreateDMSInput{ID: "ra-1", Name: "Field devices", Settings: principalSettings("ca-1", nil, map[string]string{"client_id": "x509.subject.ou"})})

	assert.ErrorIs(t, err, errs.ErrValidateBadRequest)
	assert.Empty(t, env.authz.principals)
}

// Setting what the principal of an RA grants is granting policies in authz, so it needs that permission.
// Taking grants away never does: turning the switch off, dropping policies or deleting the RA.
func TestDMSAuthzPrincipalNeedsThePermissionToGrantMore(t *testing.T) {
	// Settings are built afresh on every use: the service normalizes them in place.
	withPolicies := func(caID string, policyIDs ...string) func() models.DMSSettings {
		return func() models.DMSSettings {
			return principalSettings(caID, policyIDs, map[string]string{"device_id": "x509.subject.cn"})
		}
	}
	off := func() models.DMSSettings { return dmsSettings("ca-1", ptr(false)) }
	cases := []struct {
		name          string
		before, after func() models.DMSSettings // a nil before creates the RA
		needed        bool
	}{
		{name: "create without a principal", after: off},
		{name: "create with a principal without policies", after: withPolicies("ca-1")},
		{name: "create with policies", after: withPolicies("ca-1", "policy-a"), needed: true},
		{name: "update that keeps everything", before: withPolicies("ca-1", "policy-a", "policy-b"), after: withPolicies("ca-1", "policy-b", "policy-a", "policy-a")},
		{name: "update that omits the principal", before: withPolicies("ca-1", "policy-a"), after: func() models.DMSSettings { return dmsSettings("ca-1", nil) }},
		{name: "update that drops a policy", before: withPolicies("ca-1", "policy-a", "policy-b"), after: withPolicies("ca-1", "policy-a")},
		{name: "update that turns the switch off", before: withPolicies("ca-1", "policy-a"), after: off},
		{name: "update that adds a policy", before: withPolicies("ca-1", "policy-a"), after: withPolicies("ca-1", "policy-a", "policy-b"), needed: true},
		{name: "update that turns on a principal with policies", before: off, after: withPolicies("ca-1", "policy-a"), needed: true},
		{name: "update that changes the Enrollment CA", before: withPolicies("ca-1", "policy-a"), after: withPolicies("ca-2", "policy-a"), needed: true},
		{name: "update that changes the CA of a principal without policies", before: withPolicies("ca-1"), after: withPolicies("ca-2"), needed: true},
		{name: "update that changes a mapping", before: withPolicies("ca-1", "policy-a"), after: func() models.DMSSettings {
			return principalSettings("ca-1", []string{"policy-a"}, map[string]string{"device_id": "x509.serial_number"})
		}, needed: true},
	}
	for _, tc := range cases {
		for _, allowed := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/allowed=%v", tc.name, allowed), func(t *testing.T) {
				env := newDMSAuthzEnv(t, true)
				if tc.before != nil {
					_, err := env.svc.CreateDMS(env.ctx, services.CreateDMSInput{ID: "ra-1", Name: "Field devices", Settings: tc.before()})
					require.NoError(t, err)
				}
				before := env.snapshot(t, "ra-1")
				calls := 0
				ctx := services.WithPolicyGrantCheck(context.Background(), grantCheck(allowed, &calls))

				var err error
				if tc.before == nil {
					_, err = env.svc.CreateDMS(ctx, services.CreateDMSInput{ID: "ra-1", Name: "Field devices", Settings: tc.after()})
				} else {
					after := tc.after()
					_, err = env.svc.UpdateDMS(ctx, services.UpdateDMSInput{ID: "ra-1", Name: "Field devices", Settings: &after})
				}

				switch {
				case !tc.needed:
					require.NoError(t, err)
					assert.Zero(t, calls, "the caller is not asked")
				case allowed:
					require.NoError(t, err)
					assert.Equal(t, 1, calls)
				default:
					assert.ErrorIs(t, err, errs.ErrDMSAuthzPolicyGrantForbidden)
					assert.Equal(t, 1, calls, "the caller was asked")
					assert.Equal(t, before, env.snapshot(t, "ra-1"), "neither authz nor the stored RA change")
				}
			})
		}
	}
}

func TestDMSAuthzPrincipalGrantsNothingNewWithoutACaller(t *testing.T) {
	env := newDMSAuthzEnv(t, true)
	ctx := context.Background() // an in-process call carries no check: it can not grant on its own

	_, err := env.svc.CreateDMS(ctx, services.CreateDMSInput{ID: "ra-1", Name: "Field devices", Settings: principalSettings("ca-1", []string{"policy-a"}, nil)})
	assert.ErrorIs(t, err, errs.ErrDMSAuthzPolicyGrantForbidden)

	_, err = env.svc.CreateDMS(ctx, services.CreateDMSInput{ID: "ra-2", Name: "Field devices", Settings: principalSettings("ca-1", nil, nil)})
	assert.NoError(t, err, "a principal without policies grants nothing")

	failing := services.WithPolicyGrantCheck(ctx, func(context.Context) (bool, error) { return false, fmt.Errorf("authz down") })
	_, err = env.svc.CreateDMS(failing, services.CreateDMSInput{ID: "ra-3", Name: "Field devices", Settings: principalSettings("ca-1", []string{"policy-a"}, nil)})
	require.Error(t, err)
	assert.NotErrorIs(t, err, errs.ErrDMSAuthzPolicyGrantForbidden, "an unanswered check is an error, not a denial")
	assert.NotContains(t, env.repo.dms, "ra-3")
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
		{name: "unknown policy", id: "ra-1", ca: "ca-1", wantErr: errs.ErrValidateBadRequest, prepare: func(e *dmsAuthzEnv) { delete(e.authz.policies, "policy-b") }},
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

// A failed delete, or a second one racing a successful delete, must never bring the CA trust back.
func TestDMSAuthzPrincipalIsNotRecreatedWhenSavingFailsAfterDeletingIt(t *testing.T) {
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

			require.Error(t, fail(env))

			assert.NotContains(t, env.authz.principals, "dms:ra-1")
		})
	}
}

// Someone else's principal under the id of an RA is theirs: neither deleting the RA nor turning its switch off removes it.
func TestDMSAuthzPrincipalKeepsAPrincipalItDoesNotManage(t *testing.T) {
	cases := map[string]func(e *dmsAuthzEnv) error{
		"deleting the RA": func(e *dmsAuthzEnv) error {
			return e.svc.DeleteDMS(context.Background(), services.DeleteDMSInput{ID: "ra-1"})
		},
		"turning the switch off": func(e *dmsAuthzEnv) error { return e.update("ra-1", dmsSettings("ca-1", ptr(false))) },
	}
	for name, remove := range cases {
		t.Run(name, func(t *testing.T) {
			env := newDMSAuthzEnv(t, true)
			require.NoError(t, env.create("ra-1", "ca-1", true))
			own := &authzmodels.AuthConfig{"match_mode": "serial_and_ca"}
			env.authz.principals["dms:ra-1"] = &dto.PrincipalResponse{ID: "dms:ra-1", Type: "x509", AuthConfig: own}

			require.NoError(t, remove(env))

			assert.Equal(t, own, env.authz.principals["dms:ra-1"].AuthConfig)
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

// The check compares with what authz grants now: a stale stored RA can not grant again what authz no longer gives.
func TestDMSAuthzPrincipalComparesWithWhatAuthzGrantsNow(t *testing.T) {
	cases := []struct {
		name   string
		drift  func(t *testing.T, e *dmsAuthzEnv)
		needed bool
	}{
		{name: "nothing changed in authz", drift: func(*testing.T, *dmsAuthzEnv) {}},
		{name: "an admin revoked a policy in authz", needed: true, drift: func(_ *testing.T, e *dmsAuthzEnv) {
			e.authz.grants["dms:ra-1"] = withoutGrant(e.authz.grants["dms:ra-1"], "policy-b")
		}},
		{name: "an admin deleted the principal in authz", needed: true, drift: func(_ *testing.T, e *dmsAuthzEnv) {
			delete(e.authz.principals, "dms:ra-1")
			delete(e.authz.grants, "dms:ra-1")
		}},
		{name: "the principal trusts another CA in authz", needed: true, drift: func(_ *testing.T, e *dmsAuthzEnv) {
			p := e.authz.principals["dms:ra-1"]
			moved := dmsPrincipalAuthConfig((*x509.Certificate)(e.ca2.Certificate.Certificate), map[string]string{"device_id": "x509.subject.cn"})
			moved[dmsManagerMarker] = (*p.AuthConfig)[dmsManagerMarker]
			p.AuthConfig = &moved
		}},
		{name: "the principal was narrowed by hand in authz", needed: true, drift: func(_ *testing.T, e *dmsAuthzEnv) {
			(*e.authz.principals["dms:ra-1"].AuthConfig)["match_mode"] = "cn_and_ca"
			(*e.authz.principals["dms:ra-1"].AuthConfig)["subject_cn"] = "device-1"
		}},
		{name: "the Enrollment CA was reissued with the same key but another subject", needed: true, drift: func(t *testing.T, e *dmsAuthzEnv) {
			crt, err := chelpers.GenerateSelfSignedCertificate(e.keys["ca-1"], "another-subject")
			require.NoError(t, err)
			e.ca1.Certificate.Certificate = (*models.X509Certificate)(crt)
		}},
		{name: "the Enrollment CA was reissued with the same key", drift: func(t *testing.T, e *dmsAuthzEnv) {
			old := e.trusts("ra-1")
			crt, err := chelpers.GenerateSelfSignedCertificate(e.keys["ca-1"], "ca-1")
			require.NoError(t, err)
			e.ca1.Certificate.Certificate = (*models.X509Certificate)(crt)
			require.NotEqual(t, old, dmsPrincipalAuthConfig(crt, nil)["ca_trust"].(map[string]any)["value"], "a new certificate")
		}},
	}
	for _, tc := range cases {
		for _, allowed := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/allowed=%v", tc.name, allowed), func(t *testing.T) {
				env := newDMSAuthzEnv(t, true)
				require.NoError(t, env.create("ra-1", "ca-1", true))
				tc.drift(t, env)
				calls := 0
				ctx := services.WithPolicyGrantCheck(context.Background(), grantCheck(allowed, &calls))

				same := dmsSettings("ca-1", ptr(true))
				_, err := env.svc.UpdateDMS(ctx, services.UpdateDMSInput{ID: "ra-1", Name: "Field devices", Settings: &same})

				if tc.needed && !allowed {
					assert.ErrorIs(t, err, errs.ErrDMSAuthzPolicyGrantForbidden)
					return
				}
				require.NoError(t, err)
				assert.Equal(t, map[bool]int{true: 1, false: 0}[tc.needed], calls)
				assert.ElementsMatch(t, []string{"policy-a", "policy-b"}, env.grantedPolicies("ra-1"))
				current := dmsPrincipalAuthConfig((*x509.Certificate)(env.ca1.Certificate.Certificate), nil)
				assert.Equal(t, current["ca_trust"].(map[string]any)["value"], env.trusts("ra-1"), "the principal pins the current certificate")
			})
		}
	}
}

// Listing a policy the principal already holds, granted by someone else, grants nothing new.
func TestDMSAuthzPrincipalCanListAPolicyItAlreadyHolds(t *testing.T) {
	env := newDMSAuthzEnv(t, true)
	_, err := env.svc.CreateDMS(env.ctx, services.CreateDMSInput{ID: "ra-1", Name: "Field devices", Settings: principalSettings("ca-1", []string{"policy-a"}, nil)})
	require.NoError(t, err)
	env.authz.grants["dms:ra-1"] = append(env.authz.grants["dms:ra-1"], dto.PrincipalPolicyResponse{PolicyID: "policy-b", GrantedBy: "admin"})
	calls := 0

	both := principalSettings("ca-1", []string{"policy-a", "policy-b"}, nil)
	_, err = env.svc.UpdateDMS(services.WithPolicyGrantCheck(context.Background(), grantCheck(false, &calls)), services.UpdateDMSInput{ID: "ra-1", Name: "Field devices", Settings: &both})

	require.NoError(t, err)
	assert.Zero(t, calls)
	assert.Equal(t, []dto.PrincipalPolicyResponse{{PolicyID: "policy-a", GrantedBy: models.DMSManagerSource}, {PolicyID: "policy-b", GrantedBy: "admin"}}, env.authz.grants["dms:ra-1"])
}

// A failed save takes back the grants it made; those it revoked stay revoked, so a failure never adds access.
func TestDMSAuthzPrincipalFailedSaveTakesBackItsGrants(t *testing.T) {
	t.Run("storing the RA fails", func(t *testing.T) {
		env := newDMSAuthzEnv(t, true)
		_, err := env.svc.CreateDMS(env.ctx, services.CreateDMSInput{ID: "ra-1", Name: "Field devices", Settings: principalSettings("ca-1", []string{"policy-a"}, nil)})
		require.NoError(t, err)
		trusted := env.trusts("ra-1")
		env.repo.failUpdate = true

		require.Error(t, env.update("ra-1", principalSettings("ca-2", []string{"policy-a", "policy-b"}, nil)))

		assert.Equal(t, []string{"policy-a"}, env.grantedPolicies("ra-1"))
		assert.Equal(t, trusted, env.trusts("ra-1"))
	})
	t.Run("a grant fails half way", func(t *testing.T) {
		env := newDMSAuthzEnv(t, true)
		_, err := env.svc.CreateDMS(env.ctx, services.CreateDMSInput{ID: "ra-1", Name: "Field devices", Settings: principalSettings("ca-1", nil, nil)})
		require.NoError(t, err)
		env.authz.grantsLeft = ptr(1)

		require.Error(t, env.update("ra-1", principalSettings("ca-1", []string{"policy-a", "policy-b"}, nil)))

		assert.Empty(t, env.grantedPolicies("ra-1"), "the grant made before the failure is taken back")
	})
	t.Run("a revoked grant stays revoked", func(t *testing.T) {
		env := newDMSAuthzEnv(t, true)
		require.NoError(t, env.create("ra-1", "ca-1", true))
		env.repo.failUpdate = true

		require.Error(t, env.update("ra-1", principalSettings("ca-1", []string{"policy-a"}, nil)))

		assert.Equal(t, []string{"policy-a"}, env.grantedPolicies("ra-1"))
		assert.Equal(t, []string{"policy-a", "policy-b"}, env.repo.dms["ra-1"].Settings.AuthzPrincipalSettings.PolicyIDs, "the stored RA did not change")
	})
}

// The settings are stored even with the switch off, and granted as they are when it is turned on.
func TestDMSAuthzPrincipalSettingsAreCheckedOnEverySave(t *testing.T) {
	cases := map[string]models.AuthzPrincipalSettings{
		"an unsupported mapping source":         {SubjectAttributeMappings: map[string]string{"client_id": "x509.subject.ou"}},
		"a mapping without a name":              {SubjectAttributeMappings: map[string]string{" ": "x509.subject.cn"}},
		"a mapping name with a space":           {SubjectAttributeMappings: map[string]string{"client id": "x509.subject.cn"}},
		"a mapping name with surrounding space": {SubjectAttributeMappings: map[string]string{"client_id ": "x509.subject.cn"}},
		"an empty policy id":                    {PolicyIDs: []string{""}},
		"an empty policy id with the switch on": {Enabled: true, PolicyIDs: []string{""}},
	}
	for name, principal := range cases {
		t.Run(name, func(t *testing.T) {
			env := newDMSAuthzEnv(t, true)
			s := dmsSettings("ca-1", nil)
			s.AuthzPrincipalSettings = &principal

			_, err := env.svc.CreateDMS(env.ctx, services.CreateDMSInput{ID: "ra-1", Name: "Field devices", Settings: s})

			assert.ErrorIs(t, err, errs.ErrValidateBadRequest)
			assert.Empty(t, env.repo.dms)
			assert.Empty(t, env.authz.principals)
		})
	}
	t.Run("repeated policy ids are stored once, also with the switch off", func(t *testing.T) {
		env := newDMSAuthzEnv(t, true)
		s := principalSettings("ca-1", []string{"policy-b", "policy-a", "policy-b"}, nil)
		s.AuthzPrincipalSettings.Enabled = false

		_, err := env.svc.CreateDMS(env.ctx, services.CreateDMSInput{ID: "ra-1", Name: "Field devices", Settings: s})

		require.NoError(t, err)
		assert.Equal(t, []string{"policy-a", "policy-b"}, env.repo.dms["ra-1"].Settings.AuthzPrincipalSettings.PolicyIDs)
	})
}

func TestDMSAuthzPrincipalWarnsWithoutPolicies(t *testing.T) {
	env := newDMSAuthzEnv(t, true)

	_, err := env.svc.CreateDMS(env.ctx, services.CreateDMSInput{ID: "ra-1", Name: "Field devices", Settings: principalSettings("ca-1", nil, nil)})

	require.NoError(t, err)
	warned := slices.ContainsFunc(env.logs.AllEntries(), func(e *logrus.Entry) bool {
		return e.Level == logrus.WarnLevel && strings.Contains(e.Message, "has no policies")
	})
	assert.True(t, warned, "a principal without policies is logged")
}

func TestDMSAuthzPrincipalPolicyLookupFailureIsNotABadRequest(t *testing.T) {
	env := newDMSAuthzEnv(t, true)
	env.policyErr = &authzsdk.APIError{StatusCode: 503}

	err := env.create("ra-1", "ca-1", true)

	require.Error(t, err)
	assert.NotErrorIs(t, err, errs.ErrValidateBadRequest, "authz being down is not the caller's fault")
	assert.Empty(t, env.repo.dms)
	assert.Empty(t, env.authz.principals)
}

// A principal can outlive its switch (a crash, a failed undo); deleting the RA still removes it.
func TestDMSDeleteRemovesAPrincipalKeptWhileTheSwitchIsOff(t *testing.T) {
	env := newDMSAuthzEnv(t, true)
	require.NoError(t, env.create("ra-1", "ca-1", true))
	env.repo.dms["ra-1"].Settings.AuthzPrincipalSettings = &models.AuthzPrincipalSettings{}

	require.NoError(t, env.svc.DeleteDMS(context.Background(), services.DeleteDMSInput{ID: "ra-1"}))

	assert.NotContains(t, env.authz.principals, "dms:ra-1")
}

// Looking for a leftover principal is best effort: an RA without a principal is deleted even when authz is down.
func TestDMSDeleteDoesNotDependOnAuthzWhenTheRAHasNoPrincipal(t *testing.T) {
	env := newDMSAuthzEnv(t, true)
	require.NoError(t, env.create("ra-1", "ca-1", false))
	env.authz.failGet = true

	require.NoError(t, env.svc.DeleteDMS(context.Background(), services.DeleteDMSInput{ID: "ra-1"}))

	assert.Empty(t, env.repo.dms)
	warned := slices.ContainsFunc(env.logs.AllEntries(), func(e *logrus.Entry) bool {
		return e.Level == logrus.WarnLevel && strings.Contains(e.Message, "leftover authz principal")
	})
	assert.True(t, warned, "the failed look is logged")
}

// The dashboard sends [] and {} for what an older client stored as null: neither widens the principal.
func TestDMSAuthzPrincipalTreatsMissingAndEmptyAlike(t *testing.T) {
	env := newDMSAuthzEnv(t, true)
	_, err := env.svc.CreateDMS(env.ctx, services.CreateDMSInput{ID: "ra-1", Name: "Field devices", Settings: principalSettings("ca-1", nil, nil)})
	require.NoError(t, err)
	calls := 0

	empty := principalSettings("ca-1", []string{}, map[string]string{})
	_, err = env.svc.UpdateDMS(services.WithPolicyGrantCheck(context.Background(), grantCheck(false, &calls)), services.UpdateDMSInput{ID: "ra-1", Name: "Field devices", Settings: &empty})

	require.NoError(t, err)
	assert.Zero(t, calls)
}

// Whether a policy exists is not told to a caller who may not grant policies.
func TestDMSAuthzPrincipalDoesNotTellACallerWithoutThePermissionWhichPoliciesExist(t *testing.T) {
	env := newDMSAuthzEnv(t, true)
	calls := 0
	ctx := services.WithPolicyGrantCheck(context.Background(), grantCheck(false, &calls))

	_, err := env.svc.CreateDMS(ctx, services.CreateDMSInput{ID: "ra-1", Name: "Field devices", Settings: principalSettings("ca-1", []string{"no-such-policy"}, nil)})

	assert.ErrorIs(t, err, errs.ErrDMSAuthzPolicyGrantForbidden)
	assert.NotErrorIs(t, err, errs.ErrValidateBadRequest)
}

func TestDMSAuthzPrincipalRejectsTooManyPolicies(t *testing.T) {
	env := newDMSAuthzEnv(t, true)
	ids := make([]string, 101)
	for i := range ids {
		ids[i] = fmt.Sprintf("policy-%03d", i)
	}

	_, err := env.svc.CreateDMS(env.ctx, services.CreateDMSInput{ID: "ra-1", Name: "Field devices", Settings: principalSettings("ca-1", ids, nil)})

	assert.ErrorIs(t, err, errs.ErrValidateBadRequest)
}

// The settings of the caller are not rewritten, and a response never carries null for a list or a map.
func TestDMSAuthzPrincipalNormalizesACopyAndNeverStoresNull(t *testing.T) {
	env := newDMSAuthzEnv(t, true)
	given := principalSettings("ca-1", []string{"policy-b", "policy-a", "policy-b"}, nil)

	_, err := env.svc.CreateDMS(env.ctx, services.CreateDMSInput{ID: "ra-1", Name: "Field devices", Settings: given})

	require.NoError(t, err)
	assert.Equal(t, []string{"policy-b", "policy-a", "policy-b"}, given.AuthzPrincipalSettings.PolicyIDs, "the caller's value is untouched")
	stored := env.repo.dms["ra-1"].Settings.AuthzPrincipalSettings
	assert.Equal(t, []string{"policy-a", "policy-b"}, stored.PolicyIDs)
	raw, err := json.Marshal(stored)
	require.NoError(t, err)
	assert.JSONEq(t, `{"enabled":true,"policy_ids":["policy-a","policy-b"],"subject_attribute_mappings":{}}`, string(raw))
}

// Looking for a leftover principal is bounded: a hung authz does not hold up deleting an RA.
func TestDMSDeleteGivesUpLookingForALeftoverPrincipal(t *testing.T) {
	env := newDMSAuthzEnv(t, true)
	require.NoError(t, env.create("ra-1", "ca-1", false))
	env.authz.hang = true
	done := make(chan error, 1)

	go func() { done <- env.svc.DeleteDMS(context.Background(), services.DeleteDMSInput{ID: "ra-1"}) }()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("deleting an RA waited for a hung authz")
	}
	assert.Empty(t, env.repo.dms)
}
