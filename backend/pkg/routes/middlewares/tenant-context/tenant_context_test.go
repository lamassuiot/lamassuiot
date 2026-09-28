package tenantcontext

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

func TestMutualTLSIdentityProviderRequiresVerifiedChain(t *testing.T) {
	request := httptest.NewRequest("GET", "/tenant", nil)
	request = request.WithContext(context.WithValue(request.Context(), core.LamassuContextKeyHTTPRequest, request))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: "device-1"}}}}

	if _, err := MutualTLSIdentityProvider(request.Context()); err == nil {
		t.Fatal("expected an unverified certificate to be rejected")
	}
}

type membershipLookupCounter struct {
	calls int
}

func (repo *membershipLookupCounter) FindActiveMembership(context.Context, string, string, string) (*models.Membership, *models.Tenant, error) {
	repo.calls++
	return nil, nil, errors.New("membership lookup must not run")
}

func TestTenantContextMiddlewareRejectsRequestWithoutClientCertificate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := &membershipLookupCounter{}
	router := gin.New()
	router.Use(NewTenantContextMiddleware(repo, MutualTLSIdentityProvider))
	router.GET("/api/v2/tenants/:tenantId/resources", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	request := httptest.NewRequest(http.MethodGet, "/api/v2/tenants/tenant-a/resources", nil)
	request = request.WithContext(context.WithValue(request.Context(), core.LamassuContextKeyHTTPRequest, request))
	record := httptest.NewRecorder()
	router.ServeHTTP(record, request)

	if record.Code != http.StatusUnauthorized {
		t.Fatalf("expected missing client certificate to be rejected with 401, got %d", record.Code)
	}
	if repo.calls != 0 {
		t.Fatalf("membership lookup must not run without a verified client certificate, calls=%d", repo.calls)
	}
}

func TestMutualTLSIdentityProviderReturnsVerifiedIdentity(t *testing.T) {
	certificate := &x509.Certificate{
		Subject: pkix.Name{CommonName: "device-1"},
		Issuer:  pkix.Name{CommonName: "device-ca"},
	}
	request := httptest.NewRequest("GET", "/tenant", nil)
	request.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{certificate},
		VerifiedChains:   [][]*x509.Certificate{{certificate}},
	}
	request = request.WithContext(context.WithValue(request.Context(), core.LamassuContextKeyHTTPRequest, request))

	identity, err := MutualTLSIdentityProvider(request.Context())
	if err != nil {
		t.Fatalf("expected verified identity, got %v", err)
	}
	if identity.Issuer != "CN=device-ca" || identity.Subject != "device-1" || identity.ActorType != "MTLS" {
		t.Fatalf("unexpected identity: %+v", identity)
	}
}

func TestHTTPIdentityProviderRejectsBearerWithoutValidatedJWT(t *testing.T) {
	request := httptest.NewRequest("GET", "/tenant", nil)
	request.Header.Set("Authorization", "Bearer invalid")
	request = request.WithContext(context.WithValue(request.Context(), core.LamassuContextKeyHTTPRequest, request))

	if _, err := HTTPIdentityProvider(request.Context()); err == nil {
		t.Fatal("expected bearer authentication without validated JWT to be rejected")
	}
}

func TestHTTPIdentityProviderUsesMutualTLSWithoutBearer(t *testing.T) {
	certificate := &x509.Certificate{
		Subject: pkix.Name{CommonName: "device-1"},
		Issuer:  pkix.Name{CommonName: "device-ca"},
	}
	request := httptest.NewRequest("GET", "/tenant", nil)
	request.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{certificate},
		VerifiedChains:   [][]*x509.Certificate{{certificate}},
	}
	request = request.WithContext(context.WithValue(request.Context(), core.LamassuContextKeyHTTPRequest, request))

	identity, err := HTTPIdentityProvider(request.Context())
	if err != nil || identity.Subject != "device-1" {
		t.Fatalf("expected mTLS identity, got %+v and %v", identity, err)
	}
}

func TestJWTIdentityProviderNormalizesIdentityAndPermissions(t *testing.T) {
	request := httptest.NewRequest("GET", "/tenant", nil)
	claims := jwt.MapClaims{
		"iss":        "https://issuer.example",
		"sub":        "actor-1",
		"actor_type": "service",
		"scope":      "ca.read certificate.issue",
		"roles":      []interface{}{"operator"},
	}
	request = request.WithContext(context.WithValue(request.Context(), "JWT", &jwt.Token{Valid: true, Claims: claims}))

	identity, err := JWTIdentityProvider(request.Context())
	if err != nil {
		t.Fatalf("expected JWT identity, got %v", err)
	}
	if identity.Issuer != "https://issuer.example" || identity.Subject != "actor-1" || identity.ActorType != "SERVICE" {
		t.Fatalf("unexpected identity: %+v", identity)
	}
	if len(identity.Permissions) != 2 || identity.Permissions[0] != "ca.read" || identity.Permissions[1] != "certificate.issue" {
		t.Fatalf("unexpected permissions: %+v", identity.Permissions)
	}
}

func TestPermissionAuthorizationUsesMembershipRoleAsGrantCeiling(t *testing.T) {
	authorizer := NewPermissionAuthorizationEngine()
	tests := []struct {
		name        string
		role        models.TenantRole
		actorType   string
		permissions []string
		operation   string
		wantAllowed bool
	}{
		{name: "viewer reads without scopes", role: models.RoleViewer, actorType: "HUMAN", operation: "certificate.read", wantAllowed: true},
		{name: "viewer scope cannot grant issuance", role: models.RoleViewer, actorType: "HUMAN", permissions: []string{"certificate.issue"}, operation: "certificate.issue"},
		{name: "auditor reads audit records", role: models.RoleAuditor, actorType: "HUMAN", operation: "audit.read", wantAllowed: true},
		{name: "auditor cannot mutate", role: models.RoleAuditor, actorType: "HUMAN", operation: "device.write"},
		{name: "enroller enrolls", role: models.RoleEnroller, actorType: "DEVICE", operation: "dms.enroll", wantAllowed: true},
		{name: "enroller cannot configure DMS", role: models.RoleEnroller, actorType: "DEVICE", operation: "dms.write"},
		{name: "operator issues certificates without scopes", role: models.RoleOperator, actorType: "HUMAN", operation: "certificate.issue", wantAllowed: true},
		{name: "token scopes restrict operator grants", role: models.RoleOperator, actorType: "HUMAN", permissions: []string{"certificate.read"}, operation: "certificate.issue"},
		{name: "pki admin configures CA", role: models.RolePKIAdmin, actorType: "HUMAN", operation: "ca.write", wantAllowed: true},
		{name: "pki admin human cannot sign keys", role: models.RolePKIAdmin, actorType: "HUMAN", permissions: []string{"key.sign"}, operation: "key.sign"},
		{name: "pki admin human cannot manage keys", role: models.RolePKIAdmin, actorType: "HUMAN", permissions: []string{"key.manage"}, operation: "key.manage"},
		{name: "pki admin service signs with explicit scope", role: models.RolePKIAdmin, actorType: "SERVICE", permissions: []string{"key.sign"}, operation: "key.sign", wantAllowed: true},
		{name: "pki admin service manages keys with explicit scope", role: models.RolePKIAdmin, actorType: "SERVICE", permissions: []string{"key.manage"}, operation: "key.manage", wantAllowed: true},
		{name: "pki admin service needs explicit key scope", role: models.RolePKIAdmin, actorType: "SERVICE", operation: "key.sign"},
		{name: "viewer cannot read key material", role: models.RoleViewer, actorType: "HUMAN", permissions: []string{"key.read"}, operation: "key.read"},
		{name: "tenant admin manages membership", role: models.RoleTenantAdmin, actorType: "HUMAN", operation: "membership.write", wantAllowed: true},
		{name: "tenant admin configures device groups", role: models.RoleTenantAdmin, actorType: "HUMAN", operation: "group.write", wantAllowed: true},
		{name: "tenant admin cannot administer PKI", role: models.RoleTenantAdmin, actorType: "HUMAN", operation: "ca.write"},
		{name: "wildcard scope is not a grant", role: models.RoleViewer, actorType: "HUMAN", permissions: []string{"*"}, operation: "certificate.issue"},
		{name: "standard OIDC scopes do not restrict role grants", role: models.RoleViewer, actorType: "HUMAN", permissions: []string{"openid", "profile", "email"}, operation: "certificate.read", wantAllowed: true},
		{name: "Lamassu scopes still restrict alongside OIDC scopes", role: models.RoleOperator, actorType: "HUMAN", permissions: []string{"openid", "certificate.read"}, operation: "certificate.issue"},
		{name: "mTLS actor has no implicit role grants", role: models.RoleViewer, actorType: "MTLS", operation: "certificate.read"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := authorizer.Authorize(context.Background(), AuthorizationRequest{
				TenantContext: core.TenantContext{
					EffectiveRole: models.TenantRole(test.role),
					ActorType:     test.actorType,
					Permissions:   test.permissions,
				},
				Operation: test.operation,
			})
			if (err == nil) != test.wantAllowed {
				t.Fatalf("expected allowed=%t, got err=%v", test.wantAllowed, err)
			}
		})
	}
}

func TestJWTIdentityProviderDoesNotTreatRoleClaimsAsPermissions(t *testing.T) {
	request := httptest.NewRequest("GET", "/tenant", nil)
	claims := jwt.MapClaims{
		"iss":   "https://issuer.example",
		"sub":   "actor-1",
		"roles": []interface{}{"operator"},
	}
	request = request.WithContext(context.WithValue(request.Context(), "JWT", &jwt.Token{Valid: true, Claims: claims}))

	identity, err := JWTIdentityProvider(request.Context())
	if err != nil {
		t.Fatalf("expected valid JWT identity, got %v", err)
	}
	if len(identity.Permissions) != 0 {
		t.Fatalf("role claim must not become a token permission: %+v", identity.Permissions)
	}
}

func TestJWTIdentityProviderRejectsInvalidIdentityClaims(t *testing.T) {
	for _, claims := range []jwt.MapClaims{
		{"sub": "actor-1"},
		{"iss": "https://issuer.example", "sub": "actor-1", "actor_type": "unknown"},
	} {
		ctx := context.WithValue(context.Background(), "JWT", &jwt.Token{Valid: true, Claims: claims})
		if _, err := JWTIdentityProvider(ctx); err == nil {
			t.Fatalf("expected invalid claims to be rejected: %+v", claims)
		}
	}
}

func TestJWTIdentityProviderKeepsSameSubjectIsolatedByIssuer(t *testing.T) {
	identities := make([]AuthenticatedIdentity, 0, 2)
	for _, issuer := range []string{"https://keycloak.example", "https://cognito.example"} {
		ctx := context.WithValue(context.Background(), "JWT", &jwt.Token{Valid: true, Claims: jwt.MapClaims{
			"iss": issuer,
			"sub": "same-subject",
		}})
		identity, err := JWTIdentityProvider(ctx)
		if err != nil {
			t.Fatalf("expected identity for issuer %s, got %v", issuer, err)
		}
		identities = append(identities, identity)
	}
	if identities[0].Subject != identities[1].Subject || identities[0].Issuer == identities[1].Issuer {
		t.Fatalf("issuer must remain part of identity: %+v", identities)
	}
}

func TestResolveTenantIDUsesRouteBeforeHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	context, _ := gin.CreateTestContext(httptest.NewRecorder())
	context.Params = gin.Params{{Key: "tenantId", Value: "tenant-route"}}
	context.Request = httptest.NewRequest("GET", "/tenants/tenant-route/resource", nil)
	context.Request.Header.Set(TenantIDHeader, "tenant-route")

	tenantID, err := ResolveTenantID(context)
	if err != nil || tenantID != "tenant-route" {
		t.Fatalf("expected route tenant, got %q and %v", tenantID, err)
	}
}

func TestResolveTenantIDRejectsContradictorySources(t *testing.T) {
	gin.SetMode(gin.TestMode)
	context, _ := gin.CreateTestContext(httptest.NewRecorder())
	context.Params = gin.Params{{Key: "tenantId", Value: "tenant-route"}}
	context.Request = httptest.NewRequest("GET", "/tenants/tenant-route/resource", nil)
	context.Request.Header.Set(TenantIDHeader, "tenant-header")

	_, err := ResolveTenantID(context)
	if !errors.Is(err, ErrTenantIDConflict) {
		t.Fatalf("expected conflicting tenant sources, got %v", err)
	}
}

func TestResolveTenantIDRejectsMissingAndMalformedSources(t *testing.T) {
	for name, header := range map[string]string{
		"missing": "",
		"newline": "tenant\nother",
	} {
		t.Run(name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			context, _ := gin.CreateTestContext(httptest.NewRecorder())
			context.Request = httptest.NewRequest("GET", "/resource", nil)
			if header != "" {
				context.Request.Header.Set(TenantIDHeader, header)
			}

			_, err := ResolveTenantID(context)
			if name == "missing" && !errors.Is(err, ErrTenantIDRequired) {
				t.Fatalf("expected missing tenant error, got %v", err)
			}
			if name == "newline" && !errors.Is(err, ErrTenantIDInvalid) {
				t.Fatalf("expected malformed tenant error, got %v", err)
			}
		})
	}
}

type membershipRepoStub struct {
	membership *models.Membership
	tenant     *models.Tenant
	err        error
}

type capturingMembershipRepo struct {
	tenantID   string
	membership *models.Membership
	tenant     *models.Tenant
}

func (repo *capturingMembershipRepo) FindActiveMembership(_ context.Context, _ string, _ string, tenantID string) (*models.Membership, *models.Tenant, error) {
	repo.tenantID = tenantID
	return repo.membership, repo.tenant, nil
}

func (stub membershipRepoStub) FindActiveMembership(context.Context, string, string, string) (*models.Membership, *models.Tenant, error) {
	return stub.membership, stub.tenant, stub.err
}

func TestNewTenantContextMiddlewareResolvesMembership(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(NewTenantContextMiddleware(membershipRepoStub{
		membership: &models.Membership{
			TenantID: "tenant-1", OrganizationID: "org-1",
			IdentityIssuer: "issuer", IdentitySubject: "subject", Status: models.MembershipActive,
		},
		tenant: &models.Tenant{ID: "tenant-1", OrganizationID: "org-1", Status: models.TenantActive},
	}, func(context.Context) (AuthenticatedIdentity, error) {
		return AuthenticatedIdentity{Issuer: "issuer", Subject: "subject", ActorType: "jwt"}, nil
	}))
	router.Use(RequireTenantContextMiddleware())
	router.GET("/tenant", func(c *gin.Context) {
		context, err := core.RequireTenantContext(c.Request.Context())
		if err != nil || context.TenantID != "tenant-1" {
			c.Status(500)
			return
		}
		c.Status(204)
	})

	record := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/tenant", nil)
	request.Header.Set(TenantIDHeader, "tenant-1")
	router.ServeHTTP(record, request)

	if record.Code != 204 {
		t.Fatalf("expected no content status, got %d", record.Code)
	}
}

func TestNewTenantContextMiddlewareUsesRouteTenantAndRejectsConflict(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := &capturingMembershipRepo{
		membership: &models.Membership{
			TenantID: "tenant-route", OrganizationID: "org-1",
			IdentityIssuer: "issuer", IdentitySubject: "subject", Status: models.MembershipActive,
		},
		tenant: &models.Tenant{ID: "tenant-route", OrganizationID: "org-1", Status: models.TenantActive},
	}
	router := gin.New()
	router.Use(NewTenantContextMiddleware(repo, func(context.Context) (AuthenticatedIdentity, error) {
		return AuthenticatedIdentity{Issuer: "issuer", Subject: "subject", ActorType: "HUMAN"}, nil
	}))
	router.GET("/tenants/:tenantId/resource", func(c *gin.Context) { c.Status(204) })

	record := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/tenants/tenant-route/resource?tenantId=tenant-query", nil)
	request.Header.Set(TenantIDHeader, "tenant-route")
	router.ServeHTTP(record, request)
	if record.Code != 204 {
		t.Fatalf("expected route tenant request to pass, got %d", record.Code)
	}
	if repo.tenantID != "tenant-route" {
		t.Fatalf("expected repository to receive route tenant, got %q", repo.tenantID)
	}

	request = httptest.NewRequest("GET", "/tenants/tenant-route/resource", nil)
	request.Header.Set(TenantIDHeader, "tenant-header")
	record = httptest.NewRecorder()
	router.ServeHTTP(record, request)
	if record.Code != http.StatusBadRequest {
		t.Fatalf("expected conflicting route/header tenant to be rejected, got %d", record.Code)
	}
}

func TestNewTenantContextMiddlewareRejectsMembershipIdentityMismatch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(NewTenantContextMiddleware(membershipRepoStub{
		membership: &models.Membership{
			TenantID: "tenant-1", OrganizationID: "org-1",
			IdentityIssuer: "issuer-other", IdentitySubject: "subject", Status: models.MembershipActive,
		},
		tenant: &models.Tenant{ID: "tenant-1", OrganizationID: "org-1", Status: models.TenantActive},
	}, func(context.Context) (AuthenticatedIdentity, error) {
		return AuthenticatedIdentity{Issuer: "issuer", Subject: "subject", ActorType: "HUMAN"}, nil
	}))
	router.GET("/tenant", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	record := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/tenant", nil)
	request.Header.Set(TenantIDHeader, "tenant-1")
	router.ServeHTTP(record, request)
	if record.Code != http.StatusForbidden {
		t.Fatalf("expected a mismatched membership identity to be rejected, got %d", record.Code)
	}
}

func TestNewTenantContextMiddlewareRejectsMembershipFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(NewTenantContextMiddleware(membershipRepoStub{err: storage.ErrActiveMembershipNotFound}, func(context.Context) (AuthenticatedIdentity, error) {
		return AuthenticatedIdentity{Issuer: "issuer", Subject: "subject", ActorType: "jwt"}, nil
	}))
	router.GET("/tenant", func(c *gin.Context) { c.Status(204) })

	record := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/tenant", nil)
	request.Header.Set(TenantIDHeader, "tenant-1")
	router.ServeHTTP(record, request)

	if record.Code != 403 {
		t.Fatalf("expected forbidden status, got %d", record.Code)
	}
}

func TestNewTenantContextMiddlewareReportsLookupFailureAsUnavailable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(NewTenantContextMiddleware(membershipRepoStub{err: errors.New("connection refused")}, func(context.Context) (AuthenticatedIdentity, error) {
		return AuthenticatedIdentity{Issuer: "issuer", Subject: "subject", ActorType: "jwt"}, nil
	}))
	handled := false
	router.GET("/tenant", func(c *gin.Context) { handled = true; c.Status(204) })

	record := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/tenant", nil)
	request.Header.Set(TenantIDHeader, "tenant-1")
	router.ServeHTTP(record, request)

	if record.Code != http.StatusServiceUnavailable || handled {
		t.Fatalf("a failed membership lookup must return 503 without reaching the handler, got %d handled=%v", record.Code, handled)
	}
}

func TestNewTenantContextMiddlewareRejectsServiceWithoutMembership(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(NewTenantContextMiddleware(membershipRepoStub{}, func(context.Context) (AuthenticatedIdentity, error) {
		return AuthenticatedIdentity{Issuer: "issuer", Subject: "service-1", ActorType: "SERVICE"}, nil
	}))
	router.GET("/tenant", func(c *gin.Context) { c.Status(204) })

	record := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/tenant", nil)
	request.Header.Set(TenantIDHeader, "tenant-1")
	router.ServeHTTP(record, request)

	if record.Code != 403 {
		t.Fatalf("expected service without membership to be forbidden, got %d", record.Code)
	}
}

func TestNewTenantContextMiddlewareRejectsSuspendedMembershipOrTenant(t *testing.T) {
	for name, repository := range map[string]membershipRepoStub{
		"membership suspended": {
			membership: &models.Membership{
				TenantID: "tenant-1", OrganizationID: "org-1",
				IdentityIssuer: "issuer", IdentitySubject: "subject", Status: models.MembershipSuspended,
			},
			tenant: &models.Tenant{ID: "tenant-1", OrganizationID: "org-1", Status: models.TenantActive},
		},
		"tenant suspended": {
			membership: &models.Membership{
				TenantID: "tenant-1", OrganizationID: "org-1",
				IdentityIssuer: "issuer", IdentitySubject: "subject", Status: models.MembershipActive,
			},
			tenant: &models.Tenant{ID: "tenant-1", OrganizationID: "org-1", Status: models.TenantSuspended},
		},
	} {
		t.Run(name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			router := gin.New()
			router.Use(NewTenantContextMiddleware(repository, func(context.Context) (AuthenticatedIdentity, error) {
				return AuthenticatedIdentity{Issuer: "issuer", Subject: "subject", ActorType: "HUMAN"}, nil
			}))
			router.GET("/tenant", func(c *gin.Context) { c.Status(204) })

			record := httptest.NewRecorder()
			request := httptest.NewRequest("GET", "/tenant", nil)
			request.Header.Set(TenantIDHeader, "tenant-1")
			router.ServeHTTP(record, request)

			if record.Code != http.StatusForbidden {
				t.Fatalf("expected suspended scope to be forbidden, got %d", record.Code)
			}
		})
	}
}

func TestNewTenantContextMiddlewareRejectsIncompleteMembershipResult(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(NewTenantContextMiddleware(membershipRepoStub{}, func(context.Context) (AuthenticatedIdentity, error) {
		return AuthenticatedIdentity{Issuer: "issuer", Subject: "subject", ActorType: "jwt"}, nil
	}))
	router.GET("/tenant", func(c *gin.Context) { c.Status(204) })

	record := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/tenant", nil)
	request.Header.Set(TenantIDHeader, "tenant-1")
	router.ServeHTTP(record, request)

	if record.Code != 403 {
		t.Fatalf("expected forbidden status, got %d", record.Code)
	}
}

func TestRequireTenantContextMiddlewareRejectsMissingContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequireTenantContextMiddleware())
	router.GET("/tenant", func(c *gin.Context) { c.Status(204) })

	record := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/tenant", nil)
	router.ServeHTTP(record, request)

	if record.Code != 403 {
		t.Fatalf("expected forbidden status, got %d", record.Code)
	}
}

func TestRequireTenantContextMiddlewareAllowsValidatedContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		context := core.WithTenantContext(c.Request.Context(), core.TenantContext{
			OrganizationID: "org-1",
			TenantID:       "tenant-1",
			ActorID:        "actor-1",
			ActorType:      "jwt",
			CorrelationID:  "corr-1",
			Source:         "test",
			TenantStatus:   core.TenantActive,
			Validated:      true,
		})
		c.Request = c.Request.WithContext(context)
		c.Next()
	})
	router.Use(RequireTenantContextMiddleware())
	router.GET("/tenant", func(c *gin.Context) { c.Status(204) })

	record := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/tenant", nil)
	router.ServeHTTP(record, request)

	if record.Code != 204 {
		t.Fatalf("expected no content status, got %d", record.Code)
	}
}

func TestRequireAuthorizationMiddlewareRejectsMissingTenantContext(t *testing.T) {
	called := false
	router := gin.New()
	router.Use(RequireAuthorizationMiddleware("certificate.read", AuthorizationEngineFunc(func(context.Context, AuthorizationRequest) error {
		called = true
		return nil
	})))
	router.GET("/tenant", func(c *gin.Context) { c.Status(204) })

	record := httptest.NewRecorder()
	router.ServeHTTP(record, httptest.NewRequest("GET", "/tenant", nil))

	if record.Code != http.StatusForbidden || called {
		t.Fatalf("expected authorization to stop without tenant context, status=%d called=%v", record.Code, called)
	}
}

func TestRequireAuthorizationMiddlewarePropagatesValidatedScope(t *testing.T) {
	var received AuthorizationRequest
	router := gin.New()
	router.Use(func(c *gin.Context) {
		requestContext := withAuthenticatedIdentity(c.Request.Context(), AuthenticatedIdentity{
			Issuer: "issuer", Subject: "actor-1", ActorType: "HUMAN",
		})
		requestContext = core.WithTenantContext(requestContext, core.TenantContext{
			OrganizationID: "org-1", TenantID: "tenant-1", ActorID: "actor-1", ActorType: "HUMAN",
			CorrelationID: "corr-1", Source: "http", TenantStatus: core.TenantActive, Validated: true,
		})
		c.Request = c.Request.WithContext(requestContext)
		c.Next()
	})
	router.Use(RequireAuthorizationMiddleware("certificate.read", AuthorizationEngineFunc(func(_ context.Context, request AuthorizationRequest) error {
		received = request
		return nil
	})))
	router.GET("/tenant", func(c *gin.Context) { c.Status(204) })

	record := httptest.NewRecorder()
	router.ServeHTTP(record, httptest.NewRequest("GET", "/tenant", nil))

	if record.Code != http.StatusNoContent || received.Operation != "certificate.read" || received.TenantContext.TenantID != "tenant-1" || received.Identity.Subject != "actor-1" {
		t.Fatalf("unexpected authorization request: status=%d request=%+v", record.Code, received)
	}
}

func TestRequireAuthorizationMiddlewareRejectsDeniedOperation(t *testing.T) {
	router := gin.New()
	router.Use(func(c *gin.Context) {
		requestContext := withAuthenticatedIdentity(c.Request.Context(), AuthenticatedIdentity{Issuer: "issuer", Subject: "actor-1", ActorType: "HUMAN"})
		requestContext = core.WithTenantContext(requestContext, core.TenantContext{
			OrganizationID: "org-1", TenantID: "tenant-1", ActorID: "actor-1", ActorType: "HUMAN",
			CorrelationID: "corr-1", Source: "http", TenantStatus: core.TenantActive, Validated: true,
		})
		c.Request = c.Request.WithContext(requestContext)
		c.Next()
	})
	router.Use(RequireAuthorizationMiddleware("certificate.revoke", AuthorizationEngineFunc(func(context.Context, AuthorizationRequest) error {
		return errors.New("permission denied")
	})))
	router.GET("/tenant", func(c *gin.Context) { c.Status(204) })

	record := httptest.NewRecorder()
	router.ServeHTTP(record, httptest.NewRequest("GET", "/tenant", nil))
	if record.Code != http.StatusForbidden {
		t.Fatalf("expected denied operation, got %d", record.Code)
	}
}
