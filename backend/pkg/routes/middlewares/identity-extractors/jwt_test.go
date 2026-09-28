package identityextractors

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v4"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestJWTValidatorRejectsInvalidTokens(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	validator := JWTValidator{
		KeyFunc: func(token *jwt.Token) (interface{}, error) {
			return &privateKey.PublicKey, nil
		},
		AllowedIssuers: map[string]struct{}{"https://issuer.example": {}},
		Audience:       "lamassu-api",
		AllowedAlgos:   map[string]struct{}{jwt.SigningMethodRS256.Alg(): {}},
	}

	validClaims := jwt.MapClaims{
		"iss": "https://issuer.example",
		"aud": "lamassu-api",
		"sub": "actor-1",
		"exp": time.Now().Add(time.Minute).Unix(),
	}

	tests := []struct {
		name  string
		token *jwt.Token
	}{
		{
			name:  "wrong signature",
			token: jwt.NewWithClaims(jwt.SigningMethodRS256, validClaims),
		},
		{
			name:  "none algorithm",
			token: jwt.NewWithClaims(jwt.SigningMethodNone, validClaims),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var signingKey interface{} = otherKey
			if test.name == "none algorithm" {
				signingKey = jwt.UnsafeAllowNoneSignatureType
			}
			tokenString, err := test.token.SignedString(signingKey)
			require.NoError(t, err)

			_, err = validator.Validate(tokenString)
			require.Error(t, err)
		})
	}

	t.Run("wrong audience", func(t *testing.T) {
		claims := validClaims
		claims["aud"] = "other-api"
		token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(privateKey)
		require.NoError(t, err)

		_, err = validator.Validate(token)
		require.Error(t, err)
	})

	t.Run("untrusted issuer", func(t *testing.T) {
		claims := validClaims
		claims["iss"] = "https://other-issuer.example"
		token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(privateKey)
		require.NoError(t, err)

		_, err = validator.Validate(token)
		require.Error(t, err)
	})

	t.Run("missing expiration", func(t *testing.T) {
		claims := validClaims
		delete(claims, "exp")
		token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(privateKey)
		require.NoError(t, err)

		_, err = validator.Validate(token)
		require.Error(t, err)
	})

	t.Run("not before in the future", func(t *testing.T) {
		claims := validClaims
		claims["nbf"] = time.Now().Add(time.Minute).Unix()
		token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(privateKey)
		require.NoError(t, err)

		_, err = validator.Validate(token)
		require.Error(t, err)
	})
}

func TestJWKSResolverValidatesTokenByIssuerAndKeyID(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	issuer := "https://issuer.example"
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       &privateKey.PublicKey,
		KeyID:     "key-1",
		Algorithm: jwt.SigningMethodRS256.Alg(),
		Use:       "sig",
	}}})
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write(jwks)
	}))
	defer server.Close()

	resolver := NewJWKSResolver(server.Client(), map[string]string{issuer: server.URL}, time.Minute)
	validator := JWTValidator{
		KeyFunc:        resolver.KeyFunc,
		AllowedIssuers: map[string]struct{}{issuer: {}},
		Audience:       "lamassu-api",
		AllowedAlgos:   map[string]struct{}{jwt.SigningMethodRS256.Alg(): {}},
	}
	signedToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": issuer,
		"aud": "lamassu-api",
		"sub": "actor-1",
		"exp": time.Now().Add(time.Minute).Unix(),
	})
	signedToken.Header["kid"] = "key-1"
	token, err := signedToken.SignedString(privateKey)
	require.NoError(t, err)

	_, err = validator.Validate(token)
	require.NoError(t, err)
}

func TestNewJWTValidatorRejectsIncompleteConfiguration(t *testing.T) {
	_, err := NewJWTValidator(nil, cconfig.HttpServerJWTAuthentication{Enabled: true}, nil)
	require.Error(t, err)
}

func TestNewJWTValidatorRequiresHTTPSForConfiguredJWKS(t *testing.T) {
	_, err := NewJWTValidator(nil, cconfig.HttpServerJWTAuthentication{
		Enabled:           true,
		Audience:          "lamassu-api",
		IssuerJWKS:        []cconfig.HttpServerJWTIssuer{{Issuer: "https://issuer.example", JWKSURL: "http://issuer.example/jwks"}},
		AllowedAlgorithms: []string{jwt.SigningMethodRS256.Alg()},
		JWKSCacheTTL:      time.Minute,
	}, nil)
	require.Error(t, err)
}

func TestNewJWTValidatorUsesConfiguredIssuerAllowlist(t *testing.T) {
	validator, err := NewJWTValidator(nil, cconfig.HttpServerJWTAuthentication{
		Enabled:           true,
		Audience:          "lamassu-api",
		IssuerJWKS:        []cconfig.HttpServerJWTIssuer{{Issuer: "https://issuer.example", JWKSURL: "https://issuer.example/jwks"}},
		AllowedAlgorithms: []string{jwt.SigningMethodRS256.Alg()},
		JWKSCacheTTL:      time.Minute,
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, validator)
	require.Contains(t, validator.AllowedIssuers, "https://issuer.example")
	require.Contains(t, validator.AllowedAlgos, jwt.SigningMethodRS256.Alg())
}

func TestJWTExtractorOnlyStoresValidatedTokens(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	validator := &JWTValidator{
		KeyFunc: func(*jwt.Token) (interface{}, error) {
			return &privateKey.PublicKey, nil
		},
		AllowedIssuers: map[string]struct{}{"https://issuer.example": {}},
		Audience:       "lamassu-api",
		AllowedAlgos:   map[string]struct{}{jwt.SigningMethodRS256.Alg(): {}},
	}
	makeToken := func(key *rsa.PrivateKey) string {
		token, signErr := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": "https://issuer.example",
			"aud": "lamassu-api",
			"sub": "actor-1",
			"exp": time.Now().Add(time.Minute).Unix(),
		}).SignedString(key)
		require.NoError(t, signErr)
		return token
	}

	for _, testCase := range []struct {
		name        string
		token       string
		wantPresent bool
	}{
		{name: "invalid signature", token: makeToken(otherKey), wantPresent: false},
		{name: "valid signature", token: makeToken(privateKey), wantPresent: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
			ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)
			ctx.Request.Header.Set("Authorization", "Bearer "+testCase.token)
			JWTExtractor{
				logger:    logrus.NewEntry(logrus.New()),
				validator: validator,
			}.ExtractAuthentication(ctx, *ctx.Request)
			_, present := ctx.Get(string(IdentityExtractorJWT))
			require.Equal(t, testCase.wantPresent, present)
		})
	}
}

func TestJWKSResolverRefreshesForRotatedKeyID(t *testing.T) {
	firstKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rotatedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	issuer := "https://issuer.example"
	rotated := false
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		key := firstKey
		keyID := "key-1"
		if rotated {
			key = rotatedKey
			keyID = "key-2"
		}
		jwks, marshalErr := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       &key.PublicKey,
			KeyID:     keyID,
			Algorithm: jwt.SigningMethodRS256.Alg(),
			Use:       "sig",
		}}})
		require.NoError(t, marshalErr)
		_, _ = response.Write(jwks)
	}))
	defer server.Close()

	resolver := NewJWKSResolver(server.Client(), map[string]string{issuer: server.URL}, time.Hour)
	validator := JWTValidator{
		KeyFunc:        resolver.KeyFunc,
		AllowedIssuers: map[string]struct{}{issuer: {}},
		Audience:       "lamassu-api",
		AllowedAlgos:   map[string]struct{}{jwt.SigningMethodRS256.Alg(): {}},
	}
	newToken := func(key *rsa.PrivateKey, keyID string) string {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": issuer,
			"aud": "lamassu-api",
			"sub": "actor-1",
			"exp": time.Now().Add(time.Minute).Unix(),
		})
		token.Header["kid"] = keyID
		value, signErr := token.SignedString(key)
		require.NoError(t, signErr)
		return value
	}

	_, err = validator.Validate(newToken(firstKey, "key-1"))
	require.NoError(t, err)
	rotated = true
	_, err = validator.Validate(newToken(rotatedKey, "key-2"))
	require.NoError(t, err)
}

func TestJWTValidatorAllowsSmallClockSkew(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	now := time.Unix(1_800_000_000, 0)
	validator := JWTValidator{
		KeyFunc: func(*jwt.Token) (interface{}, error) {
			return &privateKey.PublicKey, nil
		},
		AllowedIssuers: map[string]struct{}{"https://issuer.example": {}},
		Audience:       "lamassu-api",
		AllowedAlgos:   map[string]struct{}{jwt.SigningMethodRS256.Alg(): {}},
		now:            func() time.Time { return now },
	}

	for _, testCase := range []struct {
		name      string
		expiresAt time.Time
		notBefore time.Time
		wantValid bool
	}{
		{name: "near expiration", expiresAt: now.Add(-15 * time.Second), wantValid: true},
		{name: "near not-before", expiresAt: now.Add(time.Minute), notBefore: now.Add(15 * time.Second), wantValid: true},
		{name: "expired beyond skew", expiresAt: now.Add(-45 * time.Second)},
		{name: "not-before beyond skew", expiresAt: now.Add(time.Minute), notBefore: now.Add(45 * time.Second)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			claims := jwt.MapClaims{
				"iss": "https://issuer.example",
				"aud": "lamassu-api",
				"sub": "actor-1",
				"exp": testCase.expiresAt.Unix(),
			}
			if !testCase.notBefore.IsZero() {
				claims["nbf"] = testCase.notBefore.Unix()
			}
			token, signErr := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(privateKey)
			require.NoError(t, signErr)

			_, validateErr := validator.Validate(token)
			if testCase.wantValid {
				require.NoError(t, validateErr)
			} else {
				require.Error(t, validateErr)
			}
		})
	}
}

func TestRequestMetadataRejectsSimultaneousBearerAndClientCertificate(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	validator := &JWTValidator{
		KeyFunc: func(*jwt.Token) (interface{}, error) {
			return &privateKey.PublicKey, nil
		},
		AllowedIssuers: map[string]struct{}{"https://issuer.example": {}},
		Audience:       "lamassu-api",
		AllowedAlgos:   map[string]struct{}{jwt.SigningMethodRS256.Alg(): {}},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "https://issuer.example",
		"aud": "lamassu-api",
		"sub": "jwt-actor",
		"exp": time.Now().Add(time.Minute).Unix(),
	}).SignedString(privateKey)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequestMetadataToContextMiddleware(logrus.NewEntry(logrus.New()), validator))
	handlerCalled := false
	router.GET("/", func(ctx *gin.Context) {
		handlerCalled = true
		ctx.Status(http.StatusNoContent)
	})
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{
		Subject: pkix.Name{CommonName: "certificate-actor"},
	}}}
	record := httptest.NewRecorder()
	router.ServeHTTP(record, request)

	require.Equal(t, http.StatusBadRequest, record.Code)
	require.False(t, handlerCalled)
}

func TestJWKSRefreshDoesNotBlockCachedKeyValidation(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	issuer := "https://issuer.example"
	var requests atomic.Int32
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseRefresh) }) }
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		requestNumber := requests.Add(1)
		if requestNumber == 2 {
			close(refreshStarted)
			<-releaseRefresh
		}
		jwks, marshalErr := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       &privateKey.PublicKey,
			KeyID:     "key-1",
			Algorithm: jwt.SigningMethodRS256.Alg(),
			Use:       "sig",
		}}})
		require.NoError(t, marshalErr)
		_, _ = response.Write(jwks)
	}))
	defer server.Close()
	defer release()

	resolver := NewJWKSResolver(server.Client(), map[string]string{issuer: server.URL}, time.Minute)
	knownToken := &jwt.Token{Method: jwt.SigningMethodRS256, Header: map[string]interface{}{"kid": "key-1"}, Claims: jwt.MapClaims{"iss": issuer}}
	_, err = resolver.KeyFunc(knownToken)
	require.NoError(t, err)

	unknownToken := &jwt.Token{Method: jwt.SigningMethodRS256, Header: map[string]interface{}{"kid": "rotated-key"}, Claims: jwt.MapClaims{"iss": issuer}}
	refreshResult := make(chan error, 1)
	go func() {
		_, refreshErr := resolver.KeyFunc(unknownToken)
		refreshResult <- refreshErr
	}()
	select {
	case <-refreshStarted:
	case <-time.After(time.Second):
		t.Fatal("expected JWKS refresh to start")
	}

	knownKeyResult := make(chan error, 1)
	go func() {
		_, keyErr := resolver.KeyFunc(knownToken)
		knownKeyResult <- keyErr
	}()
	select {
	case keyErr := <-knownKeyResult:
		require.NoError(t, keyErr)
	case <-time.After(250 * time.Millisecond):
		t.Fatal("cached key lookup blocked behind JWKS network request")
	}

	release()
	select {
	case <-refreshResult:
	case <-time.After(time.Second):
		t.Fatal("JWKS refresh did not finish after release")
	}
}
