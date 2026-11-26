package services

import (
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
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

// Unit tests (no Docker) of the authz principal that follows an RA; the integration suite in
// assemblers/tests/dms-manager runs the same flows against the real authz.

type dmsRepo struct {
	storage.DMSRepo
	dms                    map[string]*models.DMS
	failInsert, failUpdate bool
	failDelete             bool
	beforeUpdate           func() // runs before Update stores, to pause a save
	locks                  sync.Map
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
	if r.beforeUpdate != nil {
		r.beforeUpdate()
	}
	if r.failUpdate {
		return nil, fmt.Errorf("update failed")
	}
	r.dms[d.ID] = d
	return d, nil
}

func (r *dmsRepo) WithLock(_ context.Context, id string, fn func() error) error {
	lock, _ := r.locks.LoadOrStore(id, &sync.Mutex{})
	lock.(*sync.Mutex).Lock()
	defer lock.(*sync.Mutex).Unlock()
	return fn()
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

// saveAs creates the RA, or updates it when it exists, with the context of a caller.
func (e *dmsAuthzEnv) saveAs(ctx context.Context, id string, s models.DMSSettings) error {
	if _, exists := e.repo.dms[id]; !exists {
		_, err := e.svc.CreateDMS(ctx, services.CreateDMSInput{ID: id, Name: "Field devices", Settings: s})
		return err
	}
	_, err := e.svc.UpdateDMS(ctx, services.UpdateDMSInput{ID: id, Name: "Field devices", Settings: &s})
	return err
}

func (e *dmsAuthzEnv) deleteRA(id string) error {
	return e.svc.DeleteDMS(context.Background(), services.DeleteDMSInput{ID: id})
}

// pinned is the fingerprint a principal config holds for the certificate of a CA.
func pinned(ca *models.CACertificate) any {
	return dmsPrincipalAuthConfig((*x509.Certificate)(ca.Certificate.Certificate), nil)["ca_trust"].(map[string]any)["value"]
}

// logged tells whether a warning with the text was logged.
func (e *dmsAuthzEnv) logged(text string) bool {
	return slices.ContainsFunc(e.logs.AllEntries(), func(l *logrus.Entry) bool {
		return l.Level == logrus.WarnLevel && strings.Contains(l.Message, text)
	})
}

func (e *dmsAuthzEnv) grantedPolicies(id string) []string {
	var ids []string
	for _, g := range e.authz.grants["dms:"+id] {
		ids = append(ids, g.PolicyID)
	}
	return ids
}

func TestDMSAuthzPrincipalFollowsTheDMS(t *testing.T) {
	env := newDMSAuthzEnv(t, true)

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

	require.NoError(t, env.update("ra-1", principalSettings("ca-2", []string{"policy-b"}, map[string]string{"client_id": "x509.serial_number"})))
	assert.ElementsMatch(t, []string{"policy-b", "by-hand"}, env.grantedPolicies("ra-1"), "policies taken out of the RA are revoked")
	assert.Equal(t, map[string]any{"client_id": "x509.serial_number"}, (*env.authz.principals["dms:ra-1"].AuthConfig)["subject_attribute_mappings"])

	require.NoError(t, env.update("ra-1", dmsSettings("ca-2", ptr(false))))
	assert.NotContains(t, env.authz.principals, "dms:ra-1", "turning the switch off deletes the principal")
	require.NoError(t, env.update("ra-1", dmsSettings("ca-2", ptr(true))))
	assert.Contains(t, env.authz.principals, "dms:ra-1")
}

func TestDMSAuthzPrincipalSyncReadsEveryGrantPage(t *testing.T) {
	env := newDMSAuthzEnv(t, true)
	require.NoError(t, env.create("ra-1", "ca-1", true))
	for i := range 5 {
		env.authz.grants["dms:ra-1"] = append([]dto.PrincipalPolicyResponse{{PolicyID: fmt.Sprintf("obsolete-%d", i), GrantedBy: models.DMSManagerSource}}, env.authz.grants["dms:ra-1"]...)
	}

	require.NoError(t, env.update("ra-1", dmsSettings("ca-1", ptr(true))), "a wanted policy on a later page is not granted again")

	assert.ElementsMatch(t, []string{"policy-a", "policy-b"}, env.grantedPolicies("ra-1"), "obsolete grants on every page are revoked")
}

func TestDMSAuthzPrincipalIsOnlyKeptWhenTheFeatureIsOn(t *testing.T) {
	env := newDMSAuthzEnv(t, false)

	assert.ErrorIs(t, env.create("ra-1", "ca-1", true), errs.ErrValidateBadRequest)
	require.NoError(t, env.create("ra-2", "ca-1", false))
	assert.NoError(t, env.deleteRA("ra-2"))
}

// What authz could not use is refused, and a failed save leaves neither an RA nor a principal behind.
func TestDMSAuthzPrincipalSaveFailures(t *testing.T) {
	badMapping := func(name, source string) func() models.DMSSettings {
		return func() models.DMSSettings { return principalSettings("ca-1", nil, map[string]string{name: source}) }
	}
	tooMany := make([]string, 101)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("policy-%03d", i)
	}
	cases := []struct {
		name     string
		id       string
		settings func() models.DMSSettings // dmsSettings("ca-1", on) when nil
		prepare  func(e *dmsAuthzEnv)
		badInput bool // a 400, and not another error
	}{
		{name: "no Enrollment CA", settings: func() models.DMSSettings { return dmsSettings("", ptr(true)) }, badInput: true},
		{name: "unknown Enrollment CA", settings: func() models.DMSSettings { return dmsSettings("nope", ptr(true)) }, badInput: true},
		{name: "revoked Enrollment CA", prepare: func(e *dmsAuthzEnv) { e.ca1.Certificate.Status = models.StatusRevoked }, badInput: true},
		{name: "id with a slash", id: "ra/x", badInput: true},
		{name: "unknown policy", prepare: func(e *dmsAuthzEnv) { delete(e.authz.policies, "policy-b") }, badInput: true},
		{name: "unsupported mapping source", settings: badMapping("client_id", "x509.subject.ou"), badInput: true},
		{name: "mapping without a name", settings: badMapping(" ", "x509.subject.cn"), badInput: true},
		{name: "mapping name with a space", settings: badMapping("client id", "x509.subject.cn"), badInput: true},
		{name: "mapping name with surrounding space", settings: badMapping("client_id ", "x509.subject.cn"), badInput: true},
		{name: "empty policy id", settings: func() models.DMSSettings { return principalSettings("ca-1", []string{""}, nil) }, badInput: true},
		{name: "empty policy id, switch off", settings: func() models.DMSSettings {
			s := principalSettings("ca-1", []string{""}, nil)
			s.AuthzPrincipalSettings.Enabled = false
			return s
		}, badInput: true},
		{name: "more than 100 policies", settings: func() models.DMSSettings { return principalSettings("ca-1", tooMany, nil) }, badInput: true},
		{name: "principal of another type", prepare: func(e *dmsAuthzEnv) {
			e.authz.principals["dms:ra-1"] = &dto.PrincipalResponse{ID: "dms:ra-1", Type: "oidc"}
		}, badInput: true},
		{name: "x509 principal not managed for this RA", prepare: func(e *dmsAuthzEnv) {
			e.authz.principals["dms:ra-1"] = &dto.PrincipalResponse{ID: "dms:ra-1", Type: "x509", AuthConfig: &authzmodels.AuthConfig{"match_mode": "serial_and_ca"}}
		}, badInput: true},
		{name: "a grant fails after the principal is created", prepare: func(e *dmsAuthzEnv) { e.authz.failGrant = true }},
		{name: "storing the RA fails", prepare: func(e *dmsAuthzEnv) { e.repo.failInsert = true }},
		{name: "authz can not tell whether a policy exists", prepare: func(e *dmsAuthzEnv) { e.policyErr = &authzsdk.APIError{StatusCode: 503} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newDMSAuthzEnv(t, true)
			foreign := map[string]*dto.PrincipalResponse{}
			if tc.prepare != nil {
				tc.prepare(env)
			}
			maps.Copy(foreign, env.authz.principals)
			settings, id := dmsSettings("ca-1", ptr(true)), cmp.Or(tc.id, "ra-1")
			if tc.settings != nil {
				settings = tc.settings()
			}

			err := env.saveAs(env.ctx, id, settings)

			require.Error(t, err)
			assert.Equal(t, tc.badInput, errors.Is(err, errs.ErrValidateBadRequest), "a 400 only for what the caller got wrong")
			assert.Empty(t, env.repo.dms, "the RA is not stored")
			assert.Equal(t, foreign, env.authz.principals, "authz keeps what was there and gets nothing more")
		})
	}
}

// The settings of the caller are not rewritten, a response never carries null for a list or a map, and
// a principal without policies is allowed, with a warning.
func TestDMSAuthzPrincipalNormalizesTheSettings(t *testing.T) {
	env := newDMSAuthzEnv(t, true)
	given := principalSettings("ca-1", []string{"policy-b", "policy-a", "policy-b"}, nil)
	given.AuthzPrincipalSettings.Enabled = false // stored as they are, and granted when the switch is turned on

	require.NoError(t, env.saveAs(env.ctx, "ra-1", given))

	assert.Equal(t, []string{"policy-b", "policy-a", "policy-b"}, given.AuthzPrincipalSettings.PolicyIDs, "the caller's value is untouched")
	raw, err := json.Marshal(env.repo.dms["ra-1"].Settings.AuthzPrincipalSettings)
	require.NoError(t, err)
	assert.JSONEq(t, `{"enabled":false,"policy_ids":["policy-a","policy-b"],"subject_attribute_mappings":{}}`, string(raw))

	require.NoError(t, env.update("ra-1", principalSettings("ca-1", nil, nil)))
	assert.Contains(t, env.authz.principals, "dms:ra-1")
	assert.Empty(t, env.grantedPolicies("ra-1"))
	assert.True(t, env.logged("has no policies"))
}

// Setting what the principal of an RA grants is granting policies in authz, so it needs that permission.
// Taking grants away never does: turning the switch off, dropping policies or deleting the RA.
func TestDMSAuthzPrincipalNeedsThePermissionToGrantMore(t *testing.T) {
	// Settings are built afresh on every use: the service works on copies, but a test must not depend on it.
	withPolicies := func(caID string, policyIDs ...string) func() models.DMSSettings {
		return func() models.DMSSettings {
			return principalSettings(caID, policyIDs, map[string]string{"device_id": "x509.subject.cn"})
		}
	}
	off := func() models.DMSSettings { return dmsSettings("ca-1", ptr(false)) }
	empty := func() models.DMSSettings { return principalSettings("ca-1", []string{}, map[string]string{}) } // what the dashboard sends for null
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
		{name: "update with empty lists where there were none", before: func() models.DMSSettings { return principalSettings("ca-1", nil, nil) }, after: empty},
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
					require.NoError(t, env.saveAs(env.ctx, "ra-1", tc.before()))
				}
				before, calls := env.snapshot(t, "ra-1"), 0

				err := env.saveAs(services.WithPolicyGrantCheck(context.Background(), grantCheck(allowed, &calls)), "ra-1", tc.after())

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

// Without a check in the context (a call that did not come through the HTTP layer) a caller can not grant, a check
// that fails is an error and not a denial, and a caller who may not grant is not told which policies exist.
func TestDMSAuthzPrincipalWithoutAnAnswerFromTheCheck(t *testing.T) {
	failing := func(context.Context) (bool, error) { return false, fmt.Errorf("authz down") }
	deny := func(context.Context) (bool, error) { return false, nil }
	cases := []struct {
		name     string
		ctx      context.Context
		policies []string
		want     error // nil: any error that is not a denial
	}{
		{name: "no check", ctx: context.Background(), policies: []string{"policy-a"}, want: errs.ErrDMSAuthzPolicyGrantForbidden},
		{name: "a check that fails", ctx: services.WithPolicyGrantCheck(context.Background(), failing), policies: []string{"policy-a"}},
		{name: "an unknown policy, without the permission", ctx: services.WithPolicyGrantCheck(context.Background(), deny), policies: []string{"no-such-policy"}, want: errs.ErrDMSAuthzPolicyGrantForbidden},
		{name: "no policies need no check", ctx: context.Background(), want: errors.ErrUnsupported},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newDMSAuthzEnv(t, true)

			err := env.saveAs(tc.ctx, "ra-1", principalSettings("ca-1", tc.policies, nil))

			switch {
			case errors.Is(tc.want, errors.ErrUnsupported):
				assert.NoError(t, err)
			case tc.want != nil:
				assert.ErrorIs(t, err, tc.want)
				assert.NotErrorIs(t, err, errs.ErrValidateBadRequest)
			default:
				require.Error(t, err)
				assert.NotErrorIs(t, err, errs.ErrDMSAuthzPolicyGrantForbidden)
			}
			if err != nil {
				assert.Empty(t, env.repo.dms)
			}
		})
	}
}

// The check compares with what authz grants now: a stale stored RA can not grant again what authz no longer gives.
func TestDMSAuthzPrincipalComparesWithWhatAuthzGrantsNow(t *testing.T) {
	reissue := func(subject string) func(t *testing.T, e *dmsAuthzEnv) {
		return func(t *testing.T, e *dmsAuthzEnv) {
			crt, err := chelpers.GenerateSelfSignedCertificate(e.keys["ca-1"], subject)
			require.NoError(t, err)
			e.ca1.Certificate.Certificate = (*models.X509Certificate)(crt)
		}
	}
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
			moved := dmsPrincipalAuthConfig((*x509.Certificate)(e.ca2.Certificate.Certificate), map[string]string{"device_id": "x509.subject.cn"})
			moved[dmsManagerMarker] = (*e.authz.principals["dms:ra-1"].AuthConfig)[dmsManagerMarker]
			e.authz.principals["dms:ra-1"].AuthConfig = &moved
		}},
		{name: "the principal was narrowed by hand in authz", needed: true, drift: func(_ *testing.T, e *dmsAuthzEnv) {
			(*e.authz.principals["dms:ra-1"].AuthConfig)["match_mode"] = "cn_and_ca"
		}},
		{name: "the Enrollment CA was reissued with the same key", drift: reissue("ca-1")},
		{name: "the Enrollment CA was reissued with the same key but another subject", needed: true, drift: reissue("another-subject")},
	}
	for _, tc := range cases {
		for _, allowed := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/allowed=%v", tc.name, allowed), func(t *testing.T) {
				env := newDMSAuthzEnv(t, true)
				require.NoError(t, env.create("ra-1", "ca-1", true))
				tc.drift(t, env)
				calls := 0

				err := env.saveAs(services.WithPolicyGrantCheck(context.Background(), grantCheck(allowed, &calls)), "ra-1", dmsSettings("ca-1", ptr(true)))

				if tc.needed && !allowed {
					assert.ErrorIs(t, err, errs.ErrDMSAuthzPolicyGrantForbidden)
					return
				}
				require.NoError(t, err)
				assert.Equal(t, map[bool]int{true: 1, false: 0}[tc.needed], calls)
				assert.ElementsMatch(t, []string{"policy-a", "policy-b"}, env.grantedPolicies("ra-1"))
				assert.Equal(t, pinned(env.ca1), env.trusts("ra-1"), "the principal pins the current certificate")
			})
		}
	}
}

// Listing a policy the principal already holds, granted by someone else, grants nothing new.
func TestDMSAuthzPrincipalCanListAPolicyItAlreadyHolds(t *testing.T) {
	env := newDMSAuthzEnv(t, true)
	require.NoError(t, env.saveAs(env.ctx, "ra-1", principalSettings("ca-1", []string{"policy-a"}, nil)))
	env.authz.grants["dms:ra-1"] = append(env.authz.grants["dms:ra-1"], dto.PrincipalPolicyResponse{PolicyID: "policy-b", GrantedBy: "admin"})
	calls := 0

	err := env.saveAs(services.WithPolicyGrantCheck(context.Background(), grantCheck(false, &calls)), "ra-1", principalSettings("ca-1", []string{"policy-a", "policy-b"}, nil))

	require.NoError(t, err)
	assert.Zero(t, calls)
	assert.Equal(t, []dto.PrincipalPolicyResponse{{PolicyID: "policy-a", GrantedBy: models.DMSManagerSource}, {PolicyID: "policy-b", GrantedBy: "admin"}}, env.authz.grants["dms:ra-1"])
}

// A failed save takes back what it did in authz: the CA the principal trusts and the grants it made. Grants it
// revoked stay revoked, so a failure never adds access, and a change made by someone else in authz stays.
func TestDMSAuthzPrincipalFailedSaveTakesBackWhatItDid(t *testing.T) {
	newEnv := func(t *testing.T, s models.DMSSettings) *dmsAuthzEnv {
		env := newDMSAuthzEnv(t, true)
		require.NoError(t, env.saveAs(env.ctx, "ra-1", s))
		return env
	}
	t.Run("storing the RA fails", func(t *testing.T) {
		env := newEnv(t, principalSettings("ca-1", []string{"policy-a"}, nil))
		trusted := env.trusts("ra-1")
		env.repo.failUpdate = true

		require.Error(t, env.update("ra-1", principalSettings("ca-2", []string{"policy-a", "policy-b"}, nil)))

		assert.Equal(t, trusted, env.trusts("ra-1"), "the principal does not trust the CA that was never saved")
		assert.Equal(t, []string{"policy-a"}, env.grantedPolicies("ra-1"))
	})
	t.Run("a grant fails half way", func(t *testing.T) {
		env := newEnv(t, principalSettings("ca-1", nil, nil))
		env.authz.grantsLeft = ptr(1)

		require.Error(t, env.update("ra-1", principalSettings("ca-1", []string{"policy-a", "policy-b"}, nil)))

		assert.Empty(t, env.grantedPolicies("ra-1"), "the grant made before the failure is taken back")
	})
	t.Run("a revoked grant stays revoked", func(t *testing.T) {
		env := newEnv(t, dmsSettings("ca-1", ptr(true)))
		env.repo.failUpdate = true

		require.Error(t, env.update("ra-1", principalSettings("ca-1", []string{"policy-a"}, nil)))

		assert.Equal(t, []string{"policy-a"}, env.grantedPolicies("ra-1"))
		assert.Equal(t, []string{"policy-a", "policy-b"}, env.repo.dms["ra-1"].Settings.AuthzPrincipalSettings.PolicyIDs, "the stored RA did not change")
	})
	for _, failRead := range []bool{false, true} { // the failed save can not read the principal back to confirm it is its own
		t.Run(fmt.Sprintf("a change made in authz stays, failed read=%v", failRead), func(t *testing.T) {
			env := newEnv(t, dmsSettings("ca-1", ptr(true)))
			env.authz.grants["dms:ra-1"] = env.authz.grants["dms:ra-1"][:1]
			// While the update grants the missing policy, an admin re-pins the principal in authz. Then the update fails.
			env.authz.onGrant = func() {
				cfg := dmsPrincipalAuthConfig((*x509.Certificate)(env.ca3.Certificate.Certificate), nil)
				cfg[dmsManagerMarker] = map[string]any{"dms_id": "ra-1", "revision": "admin"}
				env.authz.principals["dms:ra-1"].AuthConfig = &cfg
				env.authz.failGet = failRead
			}

			require.Error(t, env.update("ra-1", dmsSettings("ca-2", ptr(true))))

			env.authz.failGet = false
			assert.Equal(t, pinned(env.ca3), env.trusts("ra-1"), "the admin's change stays")
		})
	}
}

// Deleting an RA, or turning its switch off, takes its principal and the grants of it; what it can not decide stays.
func TestDMSAuthzPrincipalWhenTheRAIsDeleted(t *testing.T) {
	newEnv := func(t *testing.T, on bool) *dmsAuthzEnv {
		env := newDMSAuthzEnv(t, true)
		require.NoError(t, env.create("ra-1", "ca-1", on))
		return env
	}
	t.Run("the principal and its grants go with the RA", func(t *testing.T) {
		env := newEnv(t, true)

		require.NoError(t, env.deleteRA("ra-1"))

		assert.NotContains(t, env.authz.principals, "dms:ra-1")
		assert.Empty(t, env.authz.grants["dms:ra-1"])
		assert.Empty(t, env.repo.dms)
	})
	t.Run("an RA that never had a principal is deleted", func(t *testing.T) {
		env := newEnv(t, false)

		require.NoError(t, env.deleteRA("ra-1"))

		assert.Empty(t, env.repo.dms)
	})
	for name, setup := range map[string]func(a *authzStub){"reading": func(a *authzStub) { a.failGet = true }, "deleting": func(a *authzStub) { a.failDelete = true }} {
		t.Run("an authz that fails "+name+" the principal keeps the RA and its principal", func(t *testing.T) {
			env := newEnv(t, true)
			setup(env.authz)

			require.Error(t, env.deleteRA("ra-1"))

			assert.Contains(t, env.repo.dms, "ra-1")
			assert.Contains(t, env.authz.principals, "dms:ra-1")
		})
	}
	for name, fail := range map[string]func(e *dmsAuthzEnv) error{
		"deleting the RA": func(e *dmsAuthzEnv) error { e.repo.failDelete = true; return e.deleteRA("ra-1") },
		"turning the switch off": func(e *dmsAuthzEnv) error {
			e.repo.failUpdate = true
			return e.update("ra-1", dmsSettings("ca-1", ptr(false)))
		},
	} {
		t.Run("a failed save does not bring the trust back when "+name, func(t *testing.T) {
			env := newEnv(t, true)

			require.Error(t, fail(env))

			assert.NotContains(t, env.authz.principals, "dms:ra-1")
		})
	}
	t.Run("a principal kept while the switch is off goes too", func(t *testing.T) {
		env := newEnv(t, true)
		env.repo.dms["ra-1"].Settings.AuthzPrincipalSettings = &models.AuthzPrincipalSettings{}

		require.NoError(t, env.deleteRA("ra-1"))

		assert.NotContains(t, env.authz.principals, "dms:ra-1")
	})
	for name, remove := range map[string]func(e *dmsAuthzEnv) error{
		"deleting the RA":        func(e *dmsAuthzEnv) error { return e.deleteRA("ra-1") },
		"turning the switch off": func(e *dmsAuthzEnv) error { return e.update("ra-1", dmsSettings("ca-1", ptr(false))) },
	} {
		t.Run("a principal it does not manage stays when "+name, func(t *testing.T) {
			env := newEnv(t, true)
			own := &authzmodels.AuthConfig{"match_mode": "serial_and_ca"}
			env.authz.principals["dms:ra-1"] = &dto.PrincipalResponse{ID: "dms:ra-1", Type: "x509", AuthConfig: own}

			require.NoError(t, remove(env))

			assert.Equal(t, own, env.authz.principals["dms:ra-1"].AuthConfig)
		})
	}
	// Looking for a leftover principal is best effort and bounded: authz down or hung does not hold up the delete.
	for name, setup := range map[string]func(a *authzStub){"is down": func(a *authzStub) { a.failGet = true }, "hangs": func(a *authzStub) { a.hang = true }} {
		t.Run("an RA without a principal is deleted when authz "+name, func(t *testing.T) {
			env := newEnv(t, false)
			setup(env.authz)
			done := make(chan error, 1)

			go func() { done <- env.deleteRA("ra-1") }()

			select {
			case err := <-done:
				require.NoError(t, err)
			case <-time.After(10 * time.Second):
				t.Fatal("deleting an RA waited for authz")
			}
			assert.Empty(t, env.repo.dms)
			assert.True(t, env.logged("leftover authz principal"), "the failed look is logged")
		})
	}
}

// Two overlapping saves of the CA of an RA must leave authz trusting the CA that the RA names.
func TestDMSAuthzPrincipalFollowsTheLastSavedCAWhenSavesOverlap(t *testing.T) {
	env := newDMSAuthzEnv(t, true)
	require.NoError(t, env.create("ra-1", "ca-1", true))
	paused, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	env.repo.beforeUpdate = func() { // the first save to reach the store waits there
		once.Do(func() { close(paused); <-release })
	}
	save := func(caID string) chan error {
		done := make(chan error, 1)
		go func() { done <- env.update("ra-1", dmsSettings(caID, ptr(true))) }()
		return done
	}

	a := save("ca-2")
	<-paused // A has written the principal and waits to store the RA
	b := save("ca-3")
	select {
	case <-b: // B ran entirely while A waited
	case <-time.After(300 * time.Millisecond): // B waits for A
	}
	close(release)

	require.NoError(t, <-a)
	require.NoError(t, <-b)
	stored := env.repo.dms["ra-1"].Settings.EnrollmentSettings.EnrollmentCA
	assert.Equal(t, pinned(env.cas[stored]), env.trusts("ra-1"), "the RA names %s, so authz must trust %s", stored, stored)
}
