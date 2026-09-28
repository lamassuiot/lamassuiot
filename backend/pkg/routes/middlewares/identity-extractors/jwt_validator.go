package identityextractors

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v4"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
)

const (
	maxJWKSResponseBytes = 1 << 20
	maxJWTTokenBytes     = 64 << 10
	maxUnknownKIDRefresh = 10
	unknownKIDWindow     = time.Minute
	defaultJWKSRequestTO = 5 * time.Second
	jwtClockSkew         = 30 * time.Second
)

type JWTValidator struct {
	KeyFunc        jwt.Keyfunc
	AllowedIssuers map[string]struct{}
	Audience       string
	AllowedAlgos   map[string]struct{}
	now            func() time.Time
}

func (validator JWTValidator) Validate(rawToken string) (*jwt.Token, error) {
	if len(rawToken) == 0 || len(rawToken) > maxJWTTokenBytes {
		return nil, errors.New("JWT size is invalid")
	}
	if validator.KeyFunc == nil || validator.Audience == "" || len(validator.AllowedIssuers) == 0 || len(validator.AllowedAlgos) == 0 {
		return nil, errors.New("JWT validator is not configured")
	}
	algorithms := make([]string, 0, len(validator.AllowedAlgos))
	for algorithm := range validator.AllowedAlgos {
		if algorithm == "" || algorithm == jwt.SigningMethodNone.Alg() {
			return nil, errors.New("JWT signing algorithm is not allowed")
		}
		algorithms = append(algorithms, algorithm)
	}

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(rawToken, claims, validator.KeyFunc, jwt.WithValidMethods(algorithms), jwt.WithoutClaimsValidation())
	if err != nil {
		return nil, fmt.Errorf("JWT validation failed: %w", err)
	}
	if token == nil || !token.Valid {
		return nil, errors.New("JWT is invalid")
	}
	issuer, ok := claims["iss"].(string)
	if !ok || issuer == "" {
		return nil, errors.New("JWT issuer is required")
	}
	if _, allowed := validator.AllowedIssuers[issuer]; !allowed {
		return nil, errors.New("JWT issuer is not allowed")
	}
	if subject, ok := claims["sub"].(string); !ok || subject == "" {
		return nil, errors.New("JWT subject is required")
	}
	if !claims.VerifyAudience(validator.Audience, true) {
		return nil, errors.New("JWT audience is invalid")
	}
	now := time.Now()
	if validator.now != nil {
		now = validator.now()
	}
	if !claims.VerifyExpiresAt(now.Add(-jwtClockSkew).Unix(), true) {
		return nil, errors.New("JWT expiration is missing or expired")
	}
	if !claims.VerifyNotBefore(now.Add(jwtClockSkew).Unix(), false) {
		return nil, errors.New("JWT is not yet valid")
	}
	return token, nil
}

func NewJWTValidator(config cconfig.HttpServerJWTAuthentication, client *http.Client) (*JWTValidator, error) {
	if !config.Enabled {
		return nil, nil
	}
	if config.Audience == "" || len(config.IssuerJWKSURLs) == 0 || len(config.AllowedAlgorithms) == 0 || config.JWKSCacheTTL <= 0 {
		return nil, errors.New("enabled JWT authentication requires audience, issuer JWKS URLs, allowed algorithms and positive cache TTL")
	}
	allowedIssuers := make(map[string]struct{}, len(config.IssuerJWKSURLs))
	for issuer, jwksURL := range config.IssuerJWKSURLs {
		if issuer == "" {
			return nil, errors.New("JWT issuer must not be empty")
		}
		if err := validateJWKSURL(jwksURL); err != nil {
			return nil, fmt.Errorf("invalid JWKS URL for issuer %q: %w", issuer, err)
		}
		allowedIssuers[issuer] = struct{}{}
	}
	allowedAlgos := make(map[string]struct{}, len(config.AllowedAlgorithms))
	for _, algorithm := range config.AllowedAlgorithms {
		if algorithm == "" || algorithm == jwt.SigningMethodNone.Alg() || strings.HasPrefix(algorithm, "HS") || jwt.GetSigningMethod(algorithm) == nil {
			return nil, fmt.Errorf("unsupported JWT signing algorithm %q", algorithm)
		}
		allowedAlgos[algorithm] = struct{}{}
	}
	if client == nil {
		client = &http.Client{Timeout: defaultJWKSRequestTO}
	}
	resolver := NewJWKSResolver(client, config.IssuerJWKSURLs, config.JWKSCacheTTL)
	return &JWTValidator{
		KeyFunc:        resolver.KeyFunc,
		AllowedIssuers: allowedIssuers,
		Audience:       config.Audience,
		AllowedAlgos:   allowedAlgos,
	}, nil
}

func validateJWKSURL(rawURL string) error {
	parsed, err := url.ParseRequestURI(rawURL)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("URL must be absolute and contain no user information or fragment")
	}
	if parsed.Scheme != "https" {
		return errors.New("JWKS URL must use HTTPS")
	}
	return nil
}

type JWKSResolver struct {
	client       *http.Client
	issuerURLs   map[string]string
	cacheTTL     time.Duration
	mu           sync.Mutex
	cache        map[string]jwksCacheEntry
	refreshLimit map[string]refreshWindow
	inFlight     map[string]*jwksFetchCall
}

type jwksFetchCall struct {
	done  chan struct{}
	entry jwksCacheEntry
	err   error
}

type jwksKey struct {
	key       interface{}
	algorithm string
}

type jwksCacheEntry struct {
	keys      map[string][]jwksKey
	expiresAt time.Time
}

type refreshWindow struct {
	startedAt time.Time
	count     int
}

func NewJWKSResolver(client *http.Client, issuerURLs map[string]string, cacheTTL time.Duration) *JWKSResolver {
	if client == nil {
		client = &http.Client{Timeout: defaultJWKSRequestTO}
	}
	clientCopy := *client
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	urls := make(map[string]string, len(issuerURLs))
	for issuer, jwksURL := range issuerURLs {
		urls[issuer] = jwksURL
	}
	return &JWKSResolver{
		client:       &clientCopy,
		issuerURLs:   urls,
		cacheTTL:     cacheTTL,
		cache:        make(map[string]jwksCacheEntry),
		refreshLimit: make(map[string]refreshWindow),
		inFlight:     make(map[string]*jwksFetchCall),
	}
}

func (resolver *JWKSResolver) KeyFunc(token *jwt.Token) (interface{}, error) {
	if token == nil || token.Method == nil {
		return nil, errors.New("JWT token is required")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("JWT claims are invalid")
	}
	issuer, ok := claims["iss"].(string)
	if !ok || issuer == "" {
		return nil, errors.New("JWT issuer is required")
	}
	if _, allowed := resolver.issuerURLs[issuer]; !allowed {
		return nil, errors.New("JWT issuer is not allowed")
	}
	keyID, ok := token.Header["kid"].(string)
	if !ok || keyID == "" {
		return nil, errors.New("JWT key ID is required")
	}

	resolver.mu.Lock()
	entry, cached := resolver.cache[issuer]
	if cached && time.Now().Before(entry.expiresAt) {
		if key := matchingJWKSKey(entry, keyID, token.Method.Alg()); key != nil {
			resolver.mu.Unlock()
			return key, nil
		}
		if !resolver.allowUnknownKIDRefresh(issuer) {
			resolver.mu.Unlock()
			return nil, errors.New("JWKS refresh limit reached for unknown key ID")
		}
	}
	call, refreshInFlight := resolver.inFlight[issuer]
	if !refreshInFlight {
		call = &jwksFetchCall{done: make(chan struct{})}
		resolver.inFlight[issuer] = call
	}
	resolver.mu.Unlock()

	if refreshInFlight {
		<-call.done
	} else {
		call.entry, call.err = resolver.fetch(issuer)
		resolver.mu.Lock()
		if call.err == nil {
			resolver.cache[issuer] = call.entry
		}
		delete(resolver.inFlight, issuer)
		close(call.done)
		resolver.mu.Unlock()
	}
	if call.err != nil {
		return nil, call.err
	}
	if key := matchingJWKSKey(call.entry, keyID, token.Method.Alg()); key != nil {
		return key, nil
	}
	return nil, errors.New("JWT key ID was not found in issuer JWKS")
}

func (resolver *JWKSResolver) allowUnknownKIDRefresh(issuer string) bool {
	now := time.Now()
	window := resolver.refreshLimit[issuer]
	if window.startedAt.IsZero() || now.Sub(window.startedAt) >= unknownKIDWindow {
		window = refreshWindow{startedAt: now}
	}
	if window.count >= maxUnknownKIDRefresh {
		resolver.refreshLimit[issuer] = window
		return false
	}
	window.count++
	resolver.refreshLimit[issuer] = window
	return true
}

func matchingJWKSKey(entry jwksCacheEntry, keyID, algorithm string) interface{} {
	var matching jwksKey
	count := 0
	for _, candidate := range entry.keys[keyID] {
		if candidate.algorithm != "" && candidate.algorithm != algorithm {
			continue
		}
		matching = candidate
		count++
	}
	if count != 1 {
		return nil
	}
	return matching.key
}

func (resolver *JWKSResolver) fetch(issuer string) (jwksCacheEntry, error) {
	request, err := http.NewRequest(http.MethodGet, resolver.issuerURLs[issuer], nil)
	if err != nil {
		return jwksCacheEntry{}, fmt.Errorf("create JWKS request: %w", err)
	}
	response, err := resolver.client.Do(request)
	if err != nil {
		return jwksCacheEntry{}, fmt.Errorf("fetch issuer JWKS: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return jwksCacheEntry{}, fmt.Errorf("fetch issuer JWKS: unexpected HTTP status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxJWKSResponseBytes+1))
	if err != nil {
		return jwksCacheEntry{}, fmt.Errorf("read issuer JWKS: %w", err)
	}
	if len(body) > maxJWKSResponseBytes {
		return jwksCacheEntry{}, errors.New("issuer JWKS response exceeds size limit")
	}
	var keySet jose.JSONWebKeySet
	if err := json.Unmarshal(body, &keySet); err != nil {
		return jwksCacheEntry{}, fmt.Errorf("decode issuer JWKS: %w", err)
	}
	keys := make(map[string][]jwksKey)
	for _, jwk := range keySet.Keys {
		if !jwk.IsPublic() || jwk.KeyID == "" || (jwk.Use != "" && jwk.Use != "sig") || jwk.Algorithm == jwt.SigningMethodNone.Alg() {
			continue
		}
		keys[jwk.KeyID] = append(keys[jwk.KeyID], jwksKey{key: jwk.Key, algorithm: jwk.Algorithm})
	}
	return jwksCacheEntry{keys: keys, expiresAt: time.Now().Add(resolver.cacheTTL)}, nil
}
