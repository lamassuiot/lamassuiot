package tenantcontext

import (
	"net/http"
	"strconv"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/core/v3"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"golang.org/x/time/rate"
)

// NewIdentityRateLimitMiddleware applies the same limits per authenticated
// identity and requested tenant before the tenant context is resolved, so
// throttled requests do not reach the membership lookup in the database. The
// key includes the tenant so an identity that belongs to several tenants (for
// example a service account) keeps a separate budget in each of them. Requests without a valid
// identity pass through and are rejected later by the tenant middleware.
func NewIdentityRateLimitMiddleware(config cconfig.HttpServerTenantRateLimit, identityProvider IdentityProvider) gin.HandlerFunc {
	if !config.Enabled || config.RequestsPerSecond <= 0 || config.Burst <= 0 || identityProvider == nil {
		return func(c *gin.Context) { c.Next() }
	}
	limit := newKeyedLimiter(config)
	return func(c *gin.Context) {
		if _, internal := internalServiceIdentity(c.Request.Context()); internal {
			c.Next()
			return
		}
		identity, err := identityProvider(c.Request.Context())
		if err != nil || identity.Issuer == "" || identity.Subject == "" {
			c.Next()
			return
		}
		tenantID, err := ResolveTenantID(c)
		if err != nil {
			c.Next()
			return
		}
		if !limit.allow(identity.Issuer + "\x00" + identity.Subject + "\x00" + tenantID) {
			limit.reject(c)
			return
		}
		c.Next()
	}
}

type keyedLimiter struct {
	config     cconfig.HttpServerTenantRateLimit
	mu         sync.Mutex
	limiters   map[string]*rate.Limiter
	retryAfter string
}

func newKeyedLimiter(config cconfig.HttpServerTenantRateLimit) *keyedLimiter {
	return &keyedLimiter{
		config:     config,
		limiters:   map[string]*rate.Limiter{},
		retryAfter: strconv.Itoa(max(1, int(1/config.RequestsPerSecond))),
	}
}

func (l *keyedLimiter) allow(key string) bool {
	l.mu.Lock()
	limiter, ok := l.limiters[key]
	if !ok {
		limiter = rate.NewLimiter(rate.Limit(l.config.RequestsPerSecond), l.config.Burst)
		l.limiters[key] = limiter
	}
	l.mu.Unlock()
	return limiter.Allow()
}

func (l *keyedLimiter) reject(c *gin.Context) {
	c.Header("Retry-After", l.retryAfter)
	c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "tenant request rate exceeded"})
}

// NewTenantRateLimitMiddleware limits each tenant independently with a token
// bucket, so a noisy tenant is throttled (429) without consuming the capacity
// of the others. It runs after the tenant context is resolved and keeps state
// per service instance.
func NewTenantRateLimitMiddleware(config cconfig.HttpServerTenantRateLimit) gin.HandlerFunc {
	if !config.Enabled || config.RequestsPerSecond <= 0 || config.Burst <= 0 {
		return func(c *gin.Context) { c.Next() }
	}
	limit := newKeyedLimiter(config)
	return func(c *gin.Context) {
		tenantContext, err := core.RequireTenantContext(c.Request.Context())
		if err != nil || tenantContext.ActorType == InternalServiceActorType {
			// Internal service calls are part of the platform's own work for a
			// request already counted against the tenant.
			c.Next()
			return
		}
		if !limit.allow(tenantContext.TenantID) {
			limit.reject(c)
			return
		}
		c.Next()
	}
}
