package devissuer

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	identityextractors "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/identity-extractors"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/devpki"
)

type fixture struct {
	ca     *devpki.CA
	issuer *Issuer
	client *http.Client
}

func startIssuer(t *testing.T) fixture {
	t.Helper()
	ca, err := devpki.NewCA("test monolith CA")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Issue("devissuer")
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := Start(Options{TLSCertificate: leaf.TLS})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = issuer.Close() })
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.Pool()}},
	}
	return fixture{ca: ca, issuer: issuer, client: client}
}

// validator es el validador del backend con la misma config que devprofile
// pone en los servicios, y un cliente que solo confía en la CA del monolito.
func (f fixture) validator(t *testing.T, audience string) *identityextractors.JWTValidator {
	t.Helper()
	v, err := identityextractors.NewJWTValidator(nil, cconfig.HttpServerJWTAuthentication{
		Enabled:           true,
		Audience:          audience,
		IssuerJWKS:        []cconfig.HttpServerJWTIssuer{{Issuer: f.issuer.Issuer(), JWKSURL: f.issuer.JWKSURL()}},
		AllowedAlgorithms: []string{"RS256"},
		JWKSCacheTTL:      time.Minute,
	}, f.client)
	if err != nil {
		t.Fatalf("NewJWTValidator: %v", err)
	}
	return v
}

func (f fixture) requestToken(t *testing.T, body string) (int, map[string]any) {
	t.Helper()
	resp, err := f.client.Post(f.issuer.TokenURL(), "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST token: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func (f fixture) mustToken(t *testing.T, body string) string {
	t.Helper()
	status, out := f.requestToken(t, body)
	if status != http.StatusOK {
		t.Fatalf("POST token: estado %d, cuerpo %v", status, out)
	}
	token, _ := out["access_token"].(string)
	if token == "" {
		t.Fatalf("respuesta sin access_token: %v", out)
	}
	return token
}

func TestIssuedTokenPassesBackendJWTValidator(t *testing.T) {
	f := startIssuer(t)
	raw := f.mustToken(t, `{"subject":"alice","actor_type":"HUMAN","ttl":"15m"}`)

	token, err := f.validator(t, DefaultAudience).Validate(raw)
	if err != nil {
		t.Fatalf("el validador del backend rechaza un token del emisor: %v", err)
	}
	claims := token.Claims.(jwt.MapClaims)
	if claims["iss"] != f.issuer.Issuer() || claims["sub"] != "alice" || claims["actor_type"] != "HUMAN" {
		t.Errorf("claims inesperados: %v", claims)
	}
	if !claims.VerifyAudience(DefaultAudience, true) {
		t.Errorf("aud = %v, se esperaba %s", claims["aud"], DefaultAudience)
	}
	for _, claim := range []string{"exp", "nbf", "iat"} {
		if _, ok := claims[claim]; !ok {
			t.Errorf("falta el claim %s", claim)
		}
	}
	if token.Method.Alg() != "RS256" {
		t.Errorf("algoritmo %s, se esperaba RS256", token.Method.Alg())
	}
}

func TestServiceTokenCarriesScope(t *testing.T) {
	f := startIssuer(t)
	raw := f.mustToken(t, `{"subject":"kms-operator","actor_type":"SERVICE","scope":"kms:keys:read kms:keys:sign"}`)
	token, err := f.validator(t, DefaultAudience).Validate(raw)
	if err != nil {
		t.Fatal(err)
	}
	claims := token.Claims.(jwt.MapClaims)
	if claims["actor_type"] != "SERVICE" || claims["scope"] != "kms:keys:read kms:keys:sign" {
		t.Errorf("claims inesperados: %v", claims)
	}
}

func TestTokenWithoutActorTypeOmitsClaim(t *testing.T) {
	f := startIssuer(t)
	token, err := f.validator(t, DefaultAudience).Validate(f.mustToken(t, `{"subject":"bob"}`))
	if err != nil {
		t.Fatal(err)
	}
	claims := token.Claims.(jwt.MapClaims)
	if _, ok := claims["actor_type"]; ok {
		t.Errorf("actor_type no pedido y presente: %v", claims)
	}
	exp := int64(claims["exp"].(float64))
	iat := int64(claims["iat"].(float64))
	if time.Duration(exp-iat)*time.Second != DefaultTTL {
		t.Errorf("TTL por defecto %ds, se esperaba %s", exp-iat, DefaultTTL)
	}
}

func TestTokenSignedWithAnotherKeyIsRejected(t *testing.T) {
	f := startIssuer(t)
	good, _, err := new(jwt.Parser).ParseUnverified(f.mustToken(t, `{"subject":"alice"}`), jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// Mismos claims y mismo kid, otra clave.
	forged := jwt.NewWithClaims(jwt.SigningMethodRS256, good.Claims)
	forged.Header["kid"] = good.Header["kid"]
	raw, err := forged.SignedString(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.validator(t, DefaultAudience).Validate(raw); err == nil {
		t.Fatal("un token firmado con otra clave pasa la validación")
	}
}

func TestTokenForAnotherAudienceIsRejected(t *testing.T) {
	f := startIssuer(t)
	raw := f.mustToken(t, `{"subject":"alice"}`)
	if _, err := f.validator(t, "another-api").Validate(raw); err == nil {
		t.Fatal("un token de aud lamassu-api pasa un validador de another-api")
	}
}

func TestExpiredTokenIsRejected(t *testing.T) {
	f := startIssuer(t)
	f.issuer.now = func() time.Time { return time.Now().Add(-2 * time.Hour) }
	raw := f.mustToken(t, `{"subject":"alice","ttl":"15m"}`)
	if _, err := f.validator(t, DefaultAudience).Validate(raw); err == nil {
		t.Fatal("un token caducado pasa la validación")
	}
}

func TestInvalidActorTypeIsRejected(t *testing.T) {
	f := startIssuer(t)
	for _, actor := range []string{"ADMIN", "human", "MTLS"} {
		status, out := f.requestToken(t, `{"subject":"alice","actor_type":"`+actor+`"}`)
		if status != http.StatusBadRequest {
			t.Errorf("actor_type %s: estado %d, se esperaba 400 (%v)", actor, status, out)
		}
	}
	for _, actor := range []string{"HUMAN", "SERVICE", "DEVICE"} {
		if status, out := f.requestToken(t, `{"subject":"alice","actor_type":"`+actor+`"}`); status != http.StatusOK {
			t.Errorf("actor_type %s: estado %d, se esperaba 200 (%v)", actor, status, out)
		}
	}
}

func TestTTLAboveOneHourIsRejected(t *testing.T) {
	f := startIssuer(t)
	for _, ttl := range []string{"61m", "2h", "1h0m1s"} {
		if status, out := f.requestToken(t, `{"subject":"alice","ttl":"`+ttl+`"}`); status != http.StatusBadRequest {
			t.Errorf("ttl %s: estado %d, se esperaba 400 (%v)", ttl, status, out)
		}
	}
	for _, ttl := range []string{"0s", "-5m", "abc"} {
		if status, out := f.requestToken(t, `{"subject":"alice","ttl":"`+ttl+`"}`); status != http.StatusBadRequest {
			t.Errorf("ttl %s: estado %d, se esperaba 400 (%v)", ttl, status, out)
		}
	}
	if status, out := f.requestToken(t, `{"subject":"alice","ttl":"1h"}`); status != http.StatusOK {
		t.Errorf("ttl 1h: estado %d, se esperaba 200 (%v)", status, out)
	}
}

func TestInvalidTokenRequestsAreRejected(t *testing.T) {
	f := startIssuer(t)
	for _, body := range []string{``, `{`, `{"subject":""}`, `{"subject":"alice","unknown":1}`} {
		if status, out := f.requestToken(t, body); status != http.StatusBadRequest {
			t.Errorf("cuerpo %q: estado %d, se esperaba 400 (%v)", body, status, out)
		}
	}
	resp, err := f.client.Get(f.issuer.TokenURL())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET token: estado %d, se esperaba 405", resp.StatusCode)
	}
}

func TestListensOnlyOnLoopback(t *testing.T) {
	f := startIssuer(t)
	addr := f.issuer.Addr()
	if addr == nil || !addr.IP.Equal([]byte{127, 0, 0, 1}) {
		t.Fatalf("el emisor escucha en %v, se esperaba 127.0.0.1", addr)
	}
	for name, raw := range map[string]string{"issuer": f.issuer.Issuer(), "jwks": f.issuer.JWKSURL(), "token": f.issuer.TokenURL()} {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Hostname() != "127.0.0.1" {
			t.Errorf("%s = %q, se esperaba https://127.0.0.1:…", name, raw)
		}
	}
	if !strings.HasSuffix(f.issuer.Issuer(), "/realms/"+Realm) {
		t.Errorf("issuer %q sin /realms/%s", f.issuer.Issuer(), Realm)
	}
}

func TestServesJWKSAndDiscoveryOnlyOverHTTPS(t *testing.T) {
	f := startIssuer(t)

	resp, err := f.client.Get(f.issuer.JWKSURL())
	if err != nil {
		t.Fatal(err)
	}
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	err = json.NewDecoder(resp.Body).Decode(&jwks)
	resp.Body.Close()
	if err != nil || len(jwks.Keys) != 1 {
		t.Fatalf("JWKS: %v %v", err, jwks)
	}
	key := jwks.Keys[0]
	if key["kty"] != "RSA" || key["alg"] != "RS256" || key["use"] != "sig" || key["kid"] == "" {
		t.Errorf("clave JWKS inesperada: %v", key)
	}
	if _, private := key["d"]; private {
		t.Fatal("el JWKS publica la parte privada de la clave")
	}

	resp, err = f.client.Get(f.issuer.Issuer() + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	var discovery map[string]any
	err = json.NewDecoder(resp.Body).Decode(&discovery)
	resp.Body.Close()
	if err != nil || discovery["issuer"] != f.issuer.Issuer() || discovery["jwks_uri"] != f.issuer.JWKSURL() || discovery["token_endpoint"] != f.issuer.TokenURL() {
		t.Errorf("discovery inesperado: %v %v", err, discovery)
	}

	plain := strings.Replace(f.issuer.JWKSURL(), "https://", "http://", 1)
	if resp, err := http.Get(plain); err == nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK && bytes.Contains(body, []byte(`"keys"`)) {
			t.Fatal("el JWKS se sirve también por HTTP en claro")
		}
	}

	// Un cliente que no confía en la CA del monolito no llega al JWKS.
	if _, err := (&http.Client{Timeout: 5 * time.Second}).Get(f.issuer.JWKSURL()); err == nil {
		t.Fatal("el certificado TLS del emisor se acepta sin la CA del monolito")
	}
}

func TestKeyIsEphemeral(t *testing.T) {
	first := startIssuer(t)
	second := startIssuer(t)
	a, _, _ := new(jwt.Parser).ParseUnverified(first.mustToken(t, `{"subject":"alice"}`), jwt.MapClaims{})
	b, _, _ := new(jwt.Parser).ParseUnverified(second.mustToken(t, `{"subject":"alice"}`), jwt.MapClaims{})
	if a.Header["kid"] == b.Header["kid"] {
		t.Fatal("dos arranques comparten kid")
	}
	// El token de un arranque no vale en el otro aunque se confíe en su CA.
	second.client.Transport.(*http.Transport).TLSClientConfig.RootCAs.AddCert(first.ca.Certificate())
	if _, err := second.validator(t, DefaultAudience).Validate(first.mustToken(t, `{"subject":"alice"}`)); err == nil {
		t.Fatal("un token de otro arranque pasa la validación")
	}
}

func TestTokenMethodMatchesHTTPEndpoint(t *testing.T) {
	f := startIssuer(t)
	raw, err := f.issuer.Token(TokenRequest{Subject: "provisioner", ActorType: "HUMAN"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.validator(t, DefaultAudience).Validate(raw); err != nil {
		t.Fatalf("token emitido en proceso rechazado: %v", err)
	}
	if _, err := f.issuer.Token(TokenRequest{Subject: "alice", TTL: "2h"}); err == nil {
		t.Fatal("Token acepta un TTL mayor de 1 h")
	}
}

func TestStartRequiresTLSCertificate(t *testing.T) {
	if _, err := Start(Options{}); err == nil {
		t.Fatal("Start arranca sin certificado TLS")
	}
}
