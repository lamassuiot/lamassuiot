// Package devissuer es el emisor local de tokens del monolito de desarrollo
// (spec 009, decisiones P2 y P7). Sirve por HTTPS en 127.0.0.1 un JWKS, un
// discovery mínimo y un endpoint que firma tokens RS256 para cualquier
// identidad de prueba, sin autenticación. La clave RSA se genera en cada
// arranque y solo vive en memoria.
//
// Riesgo aceptado (P7): cualquier proceso local puede pedir un token de
// cualquier identidad, incluido el provisioner. Por eso el issuer solo se
// configura en este monolito y el emisor nunca escucha fuera de loopback.
package devissuer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v4"
)

const (
	// Realm es el realm del emisor local; forma parte del issuer.
	Realm = "lamassu-dev"
	// DefaultAudience coincide con devprofile.DefaultAudience (fast-lane).
	DefaultAudience = "lamassu-api"
	// DefaultTTL es la vida de un token si la petición no la indica.
	DefaultTTL = 15 * time.Minute
	// MaxTTL es la vida máxima que admite el endpoint de tokens.
	MaxTTL = time.Hour

	// listenAddress no es configurable: el emisor solo escucha en loopback.
	listenAddress   = "127.0.0.1"
	maxRequestBytes = 4 << 10
	maxSubjectBytes = 256
	rsaKeyBits      = 2048
)

// allowedActorTypes son los que acepta tenantcontext.JWTIdentityProvider.
var allowedActorTypes = map[string]struct{}{"HUMAN": {}, "SERVICE": {}, "DEVICE": {}}

// Options configura el emisor. El certificado TLS lo firma la CA del
// monolito (devpki).
type Options struct {
	TLSCertificate tls.Certificate
	// Audience de los tokens. Vacía: DefaultAudience.
	Audience string
}

// TokenRequest es el cuerpo de POST /realms/lamassu-dev/token.
type TokenRequest struct {
	Subject   string `json:"subject"`
	ActorType string `json:"actor_type,omitempty"`
	Scope     string `json:"scope,omitempty"`
	// TTL en formato de time.ParseDuration ("15m"). Vacío: DefaultTTL.
	TTL string `json:"ttl,omitempty"`
}

// TokenResponse es la respuesta del endpoint de tokens.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

// Issuer es un emisor en marcha.
type Issuer struct {
	key      *rsa.PrivateKey
	keyID    string
	audience string
	addr     *net.TCPAddr
	base     string
	server   *http.Server
	now      func() time.Time
}

// Start arranca el emisor en 127.0.0.1, en un puerto libre, con una clave RSA
// nueva.
func Start(opts Options) (*Issuer, error) {
	if len(opts.TLSCertificate.Certificate) == 0 || opts.TLSCertificate.PrivateKey == nil {
		return nil, errors.New("devissuer: a TLS certificate signed by the monolith CA is required")
	}
	key, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return nil, fmt.Errorf("devissuer: generate signing key: %w", err)
	}
	kid := make([]byte, 16)
	if _, err := rand.Read(kid); err != nil {
		return nil, fmt.Errorf("devissuer: generate key id: %w", err)
	}
	audience := opts.Audience
	if audience == "" {
		audience = DefaultAudience
	}

	listener, err := net.Listen("tcp", net.JoinHostPort(listenAddress, "0"))
	if err != nil {
		return nil, fmt.Errorf("devissuer: listen on %s: %w", listenAddress, err)
	}
	addr := listener.Addr().(*net.TCPAddr)

	issuer := &Issuer{
		key:      key,
		keyID:    hex.EncodeToString(kid),
		audience: audience,
		addr:     addr,
		base:     fmt.Sprintf("https://%s/realms/%s", addr.String(), Realm),
		now:      time.Now,
	}

	mux := http.NewServeMux()
	prefix := "/realms/" + Realm
	mux.HandleFunc(prefix+"/jwks", issuer.handleJWKS)
	mux.HandleFunc(prefix+"/.well-known/openid-configuration", issuer.handleDiscovery)
	mux.HandleFunc(prefix+"/token", issuer.handleToken)

	issuer.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{opts.TLSCertificate},
			MinVersion:   tls.VersionTLS12,
		},
	}
	go func() {
		_ = issuer.server.Serve(tls.NewListener(listener, issuer.server.TLSConfig))
	}()
	return issuer, nil
}

// Issuer es el valor de iss de los tokens: https://127.0.0.1:<puerto>/realms/lamassu-dev.
func (i *Issuer) Issuer() string { return i.base }

// JWKSURL es la URL del JWKS.
func (i *Issuer) JWKSURL() string { return i.base + "/jwks" }

// TokenURL es la URL del endpoint de tokens.
func (i *Issuer) TokenURL() string { return i.base + "/token" }

// Addr es la dirección en la que escucha el emisor.
func (i *Issuer) Addr() *net.TCPAddr { return i.addr }

// Close para el emisor; la clave se pierde con él.
func (i *Issuer) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return i.server.Shutdown(ctx)
}

// Token firma un token con las mismas reglas que el endpoint HTTP. Lo usa el
// propio monolito (datos de ejemplo, pruebas) sin pasar por la red.
func (i *Issuer) Token(req TokenRequest) (string, error) {
	signed, _, err := i.sign(req)
	return signed, err
}

func (i *Issuer) sign(req TokenRequest) (string, time.Duration, error) {
	if req.Subject == "" || len(req.Subject) > maxSubjectBytes {
		return "", 0, fmt.Errorf("subject is required and must be at most %d bytes", maxSubjectBytes)
	}
	if req.ActorType != "" {
		if _, ok := allowedActorTypes[req.ActorType]; !ok {
			return "", 0, fmt.Errorf("actor_type %q is not allowed: use HUMAN, SERVICE or DEVICE", req.ActorType)
		}
	}
	ttl := DefaultTTL
	if req.TTL != "" {
		parsed, err := time.ParseDuration(req.TTL)
		if err != nil {
			return "", 0, fmt.Errorf("ttl %q is not a valid duration", req.TTL)
		}
		ttl = parsed
	}
	if ttl <= 0 || ttl > MaxTTL {
		return "", 0, fmt.Errorf("ttl must be positive and at most %s", MaxTTL)
	}

	now := i.now()
	claims := jwt.MapClaims{
		"iss": i.base,
		"sub": req.Subject,
		"aud": i.audience,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(ttl).Unix(),
	}
	if req.ActorType != "" {
		claims["actor_type"] = req.ActorType
	}
	if req.Scope != "" {
		claims["scope"] = req.Scope
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = i.keyID
	signed, err := token.SignedString(i.key)
	if err != nil {
		return "", 0, fmt.Errorf("sign token: %w", err)
	}
	return signed, ttl, nil
}

func (i *Issuer) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       &i.key.PublicKey,
		KeyID:     i.keyID,
		Algorithm: "RS256",
		Use:       "sig",
	}}})
}

func (i *Issuer) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                i.base,
		"jwks_uri":                              i.JWKSURL(),
		"token_endpoint":                        i.TokenURL(),
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (i *Issuer) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req TokenRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid token request: "+strings.TrimPrefix(err.Error(), "json: "))
		return
	}
	signed, ttl, err := i.sign(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, TokenResponse{AccessToken: signed, TokenType: "Bearer", ExpiresIn: int64(ttl / time.Second)})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
