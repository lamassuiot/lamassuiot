package tenantcontext

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	identityextractors "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/identity-extractors"
	"github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

const (
	TenantIDHeader       = "X-Tenant-ID"
	LegacyTenantIDHeader = "X-LMS-Tenant-ID"
)

var (
	ErrTenantIDRequired = errors.New("tenant id is required")
	ErrTenantIDInvalid  = errors.New("tenant id is invalid")
	ErrTenantIDConflict = errors.New("tenant id sources conflict")
)

type AuthenticatedIdentity struct {
	Issuer    string
	Subject   string
	ActorType string
	// Permissions carries optional JWT scope restrictions; membership role grants remain authoritative.
	Permissions []string
}

type IdentityProvider func(context.Context) (AuthenticatedIdentity, error)

func HTTPIdentityProvider(ctx context.Context) (AuthenticatedIdentity, error) {
	request, ok := ctx.Value(core.LamassuContextKeyHTTPRequest).(*http.Request)
	if !ok || request == nil {
		return AuthenticatedIdentity{}, errors.New("HTTP request identity is unavailable")
	}
	if strings.TrimSpace(request.Header.Get("Authorization")) != "" {
		return JWTIdentityProvider(ctx)
	}
	return MutualTLSIdentityProvider(ctx)
}

func MutualTLSIdentityProvider(ctx context.Context) (AuthenticatedIdentity, error) {
	request, ok := ctx.Value(core.LamassuContextKeyHTTPRequest).(*http.Request)
	if !ok || request == nil || request.TLS == nil || len(request.TLS.VerifiedChains) == 0 || len(request.TLS.PeerCertificates) == 0 {
		return AuthenticatedIdentity{}, errors.New("verified mutual TLS identity is unavailable")
	}

	certificate := request.TLS.PeerCertificates[0]
	if certificate.Subject.CommonName == "" {
		return AuthenticatedIdentity{}, errors.New("mutual TLS certificate subject is required")
	}
	return AuthenticatedIdentity{
		Issuer:    certificate.Issuer.String(),
		Subject:   certificate.Subject.CommonName,
		ActorType: "MTLS",
	}, nil
}

func JWTIdentityProvider(ctx context.Context) (AuthenticatedIdentity, error) {
	value := ctx.Value(string(identityextractors.IdentityExtractorJWT))
	token, ok := value.(*jwt.Token)
	if !ok || token == nil || !token.Valid {
		return AuthenticatedIdentity{}, errors.New("validated JWT identity is unavailable")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return AuthenticatedIdentity{}, errors.New("validated JWT claims are unavailable")
	}
	issuer, issuerOK := claims["iss"].(string)
	subject, subjectOK := claims["sub"].(string)
	if !issuerOK || issuer == "" || !subjectOK || subject == "" {
		return AuthenticatedIdentity{}, errors.New("JWT issuer and subject are required")
	}

	actorType := "HUMAN"
	if value, ok := claims["actor_type"].(string); ok && value != "" {
		actorType = strings.ToUpper(value)
	} else if _, ok := claims["azp"]; ok {
		actorType = "SERVICE"
	} else if _, ok := claims["client_id"]; ok {
		actorType = "SERVICE"
	}
	if actorType != "HUMAN" && actorType != "SERVICE" && actorType != "DEVICE" {
		return AuthenticatedIdentity{}, errors.New("unsupported JWT actor type")
	}

	return AuthenticatedIdentity{
		Issuer:      issuer,
		Subject:     subject,
		ActorType:   actorType,
		Permissions: jwtPermissions(claims),
	}, nil
}

func jwtPermissions(claims jwt.MapClaims) []string {
	permissions := make([]string, 0)
	if scope, ok := claims["scope"].(string); ok {
		permissions = append(permissions, strings.Fields(scope)...)
	}
	return permissions
}

func ResolveTenantID(c *gin.Context) (string, error) {
	routeTenantID := strings.TrimSpace(c.Param("tenantId"))
	if routeTenantID == "" {
		routeTenantID = strings.TrimSpace(c.Param("tenantID"))
	}
	if routeTenantID != "" && !validTenantID(routeTenantID) {
		return "", ErrTenantIDInvalid
	}

	headerTenantID := strings.TrimSpace(c.GetHeader(TenantIDHeader))
	legacyHeaderTenantID := strings.TrimSpace(c.GetHeader(LegacyTenantIDHeader))
	if headerTenantID != "" && legacyHeaderTenantID != "" && headerTenantID != legacyHeaderTenantID {
		return "", ErrTenantIDConflict
	}
	if headerTenantID == "" {
		headerTenantID = legacyHeaderTenantID
	}
	if headerTenantID != "" && !validTenantID(headerTenantID) {
		return "", ErrTenantIDInvalid
	}

	if routeTenantID != "" && headerTenantID != "" && routeTenantID != headerTenantID {
		return "", ErrTenantIDConflict
	}
	if routeTenantID != "" {
		return routeTenantID, nil
	}
	if headerTenantID != "" {
		return headerTenantID, nil
	}
	return "", ErrTenantIDRequired
}

func validTenantID(tenantID string) bool {
	if tenantID == "" || len(tenantID) > 128 {
		return false
	}
	for _, character := range tenantID {
		if character < 0x21 || character == 0x7f {
			return false
		}
	}
	return true
}

func NewTenantContextMiddleware(repo storage.ControlPlaneMembershipRepo, identityProvider IdentityProvider) gin.HandlerFunc {
	return func(c *gin.Context) {
		if repo == nil || identityProvider == nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "tenant context is not configured"})
			return
		}

		if internal, ok := internalServiceIdentity(c.Request.Context()); ok {
			resolveInternalServiceTenantContext(c, repo, internal)
			return
		}

		identity, err := identityProvider(c.Request.Context())
		if err != nil || identity.Issuer == "" || identity.Subject == "" || identity.ActorType == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authenticated identity is required"})
			return
		}

		tenantID, err := ResolveTenantID(c)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid tenant context"})
			return
		}

		membership, tenant, err := repo.FindActiveMembership(c.Request.Context(), identity.Issuer, identity.Subject, tenantID)
		if err != nil && !errors.Is(err, storage.ErrActiveMembershipNotFound) {
			// The lookup itself failed (database unavailable, pool exhausted…):
			// report it as a service error, never as an authorization denial.
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "tenant context temporarily unavailable"})
			return
		}
		if err != nil || membership == nil || tenant == nil ||
			membership.IdentityIssuer != identity.Issuer || membership.IdentitySubject != identity.Subject {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "tenant access denied"})
			return
		}

		correlationID := c.GetHeader(models.HttpRequestIDHeader)
		if correlationID == "" {
			correlationID = uuid.NewString()
		}
		source, _ := c.Request.Context().Value(core.LamassuContextKeySource).(string)
		if source == "" {
			source = "http"
		}

		tenantContext, err := core.NewValidatedTenantContext(*membership, *tenant, identity.Subject, identity.ActorType, identity.Permissions, correlationID, source)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "tenant access denied"})
			return
		}
		requestContext := withAuthenticatedIdentity(c.Request.Context(), identity)
		requestContext = core.WithTenantContext(requestContext, tenantContext)
		c.Request = c.Request.WithContext(requestContext)
		c.Next()
	}
}

// resolveInternalServiceTenantContext builds the context of a call made by
// another Lamassu service through the internal listener. The caller already
// validated the end user's membership in the original request; here the
// tenant must exist and be ACTIVE, and no membership is looked up.
func resolveInternalServiceTenantContext(c *gin.Context, repo storage.ControlPlaneMembershipRepo, identity AuthenticatedIdentity) {
	tenants, ok := repo.(storage.ActiveTenantGetter)
	if !ok {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "tenant resolution is not configured"})
		return
	}
	tenantID, err := ResolveTenantID(c)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid tenant context"})
		return
	}
	tenant, err := tenants.GetActiveTenant(c.Request.Context(), tenantID)
	if err != nil && !errors.Is(err, storage.ErrActiveMembershipNotFound) {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "tenant context temporarily unavailable"})
		return
	}
	if err != nil || tenant == nil {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "tenant access denied"})
		return
	}
	correlationID := c.GetHeader(models.HttpRequestIDHeader)
	if correlationID == "" {
		correlationID = uuid.NewString()
	}
	requestContext := withAuthenticatedIdentity(c.Request.Context(), identity)
	requestContext = core.WithTenantContext(requestContext, core.TenantContext{
		OrganizationID: tenant.OrganizationID,
		TenantID:       tenant.ID,
		ActorID:        identity.Subject,
		ActorType:      InternalServiceActorType,
		CorrelationID:  correlationID,
		Source:         "internal-service",
		TenantStatus:   core.TenantActive,
		Validated:      true,
	})
	c.Request = c.Request.WithContext(requestContext)
	c.Next()
}

func RequireTenantContextMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, err := core.RequireTenantContext(c.Request.Context()); err != nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "tenant context is required"})
			return
		}
		c.Next()
	}
}
