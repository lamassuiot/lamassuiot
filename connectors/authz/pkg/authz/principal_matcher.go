package authz

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lamassuiot/authz/pkg/models"
)

// OIDCMatcher matches principals against JWT/OIDC auth material.
// Zero fields, zero dependencies — safe to use as a value or package-level singleton.
type OIDCMatcher struct{}

// X509Matcher matches principals against X.509 certificate auth material.
// Zero fields, zero dependencies — safe to use as a value or package-level singleton.
type X509Matcher struct{}

// Match filters principals whose AuthConfig claim conditions all pass for the given JWT material.
// authMaterial accepts: string (Bearer token or raw JWT), jwt.MapClaims, map[string]interface{}.
func (OIDCMatcher) Match(principals []models.Principal, authMaterial interface{}) ([]string, error) {
	claims, err := extractOIDCClaims(authMaterial)
	if err != nil {
		return nil, err
	}

	matched := make([]string, 0)
	for _, p := range principals {
		ok, err := matchOIDCClaims(&p, claims)
		if err != nil {
			continue // per-principal errors are non-fatal
		}
		if ok {
			matched = append(matched, p.ID)
		}
	}
	return matched, nil
}

// Match filters principals whose AuthConfig matches the given certificate material.
// authMaterial accepts: *x509.Certificate or string (PEM-encoded certificate).
func (X509Matcher) Match(principals []models.Principal, authMaterial interface{}) ([]string, error) {
	cert, err := extractX509Cert(authMaterial)
	if err != nil {
		return nil, err
	}

	matched := make([]string, 0)
	for _, p := range principals {
		ok, err := matchX509Cert(&p, cert)
		if err != nil {
			continue // per-principal errors are non-fatal
		}
		if ok {
			matched = append(matched, p.ID)
		}
	}
	return matched, nil
}

// MatchService coordinates loading active principals from the store and dispatching
// to the correct PrincipalMatcher by auth type. It is the only place that knows
// the mapping from authType string to PrincipalMatcher implementation.
type MatchService struct {
	store    PrincipalStore
	matchers map[string]PrincipalMatcher
}

// NewMatchService creates a MatchService with the given store and matcher dispatch table.
func NewMatchService(store PrincipalStore, matchers map[string]PrincipalMatcher) *MatchService {
	return &MatchService{store: store, matchers: matchers}
}

// DefaultMatchService returns a MatchService wired with the standard OIDC and X.509 matchers.
func DefaultMatchService(store PrincipalStore) *MatchService {
	return NewMatchService(store, map[string]PrincipalMatcher{
		"oidc": OIDCMatcher{},
		"x509": X509Matcher{},
	})
}

// MatchPrincipals loads active principals of authType from the store and returns those
// whose AuthConfig matches authMaterial. Drop-in replacement for PrincipalManager.MatchPrincipals.
func (ms *MatchService) MatchPrincipals(ctx context.Context, authMaterial interface{}, authType string) ([]string, error) {
	matcher, ok := ms.matchers[authType]
	if !ok {
		return nil, fmt.Errorf("unsupported auth type: %s", authType)
	}
	principals, err := ms.store.ListByType(ctx, authType)
	if err != nil {
		return nil, fmt.Errorf("load principals for matching: %w", err)
	}
	return matcher.Match(principals, authMaterial)
}

// --- OIDC helpers ---

func extractOIDCClaims(authMaterial interface{}) (jwt.MapClaims, error) {
	switch v := authMaterial.(type) {
	case jwt.MapClaims:
		return v, nil
	case map[string]interface{}:
		return jwt.MapClaims(v), nil
	case string:
		v = strings.TrimPrefix(v, "Bearer ")
		parser := jwt.NewParser()
		var claims jwt.MapClaims
		_, _, err := parser.ParseUnverified(v, &claims)
		if err != nil {
			return nil, fmt.Errorf("failed to parse JWT token: %w", err)
		}
		if claims == nil {
			return nil, fmt.Errorf("invalid JWT claims format")
		}
		return claims, nil
	default:
		return nil, fmt.Errorf("invalid OIDC auth material format")
	}
}

func matchOIDCClaims(p *models.Principal, claims jwt.MapClaims) (bool, error) {
	claimConditions, ok := p.AuthConfig["claims"].([]interface{})
	if !ok {
		return false, fmt.Errorf("missing or invalid claims in auth_config for principal %s", p.ID)
	}
	for _, ci := range claimConditions {
		condition, ok := ci.(map[string]interface{})
		if !ok {
			continue
		}
		claimName, _ := condition["claim"].(string)
		operator, _ := condition["operator"].(string)
		expectedValue := condition["value"]
		if !evaluateClaim(claims, claimName, operator, expectedValue) {
			return false, nil
		}
	}
	return true, nil
}

func getNestedClaim(claims jwt.MapClaims, claimPath string) (interface{}, bool) {
	parts := strings.Split(claimPath, ".")
	var current interface{} = claims
	for _, part := range parts {
		var currentMap map[string]interface{}
		switch v := current.(type) {
		case jwt.MapClaims:
			currentMap = v
		case map[string]interface{}:
			currentMap = v
		default:
			return nil, false
		}
		next, exists := currentMap[part]
		if !exists {
			return nil, false
		}
		current = next
	}
	return current, true
}

func evaluateClaim(claims jwt.MapClaims, claimName, operator string, expectedValue interface{}) bool {
	actualValue, exists := getNestedClaim(claims, claimName)
	if !exists {
		return false
	}
	switch operator {
	case "equals":
		return fmt.Sprintf("%v", actualValue) == fmt.Sprintf("%v", expectedValue)
	case "contains":
		if arr, ok := actualValue.([]interface{}); ok {
			expectedStr := fmt.Sprintf("%v", expectedValue)
			for _, item := range arr {
				if fmt.Sprintf("%v", item) == expectedStr {
					return true
				}
			}
			return false
		}
		return strings.Contains(fmt.Sprintf("%v", actualValue), fmt.Sprintf("%v", expectedValue))
	case "matches":
		// TODO: implement regex matching
		return false
	default:
		return false
	}
}

// --- X.509 helpers ---

func extractX509Cert(authMaterial interface{}) (*x509.Certificate, error) {
	switch v := authMaterial.(type) {
	case *x509.Certificate:
		return v, nil
	case string:
		block, _ := pem.Decode([]byte(v))
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM block")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		return cert, nil
	default:
		return nil, fmt.Errorf("invalid x509 auth material format")
	}
}

func matchX509Cert(p *models.Principal, cert *x509.Certificate) (bool, error) {
	matchMode, ok := p.AuthConfig["match_mode"].(string)
	if !ok {
		return false, fmt.Errorf("missing match_mode in auth_config for principal %s", p.ID)
	}
	switch matchMode {
	case "serial_and_ca":
		return matchX509SerialAndCA(p, cert)
	case "cn", "cn_and_ca":
		return matchX509CN(p, cert)
	case "any_from_ca":
		return checkCA(p, cert)
	default:
		return false, fmt.Errorf("invalid match_mode %q for principal %s", matchMode, p.ID)
	}
}

func matchX509SerialAndCA(p *models.Principal, cert *x509.Certificate) (bool, error) {
	requiredSerial, ok := p.AuthConfig["serial_number"].(string)
	if !ok {
		return false, fmt.Errorf("missing serial_number in auth_config")
	}
	actualSerial := strings.ToUpper(cert.SerialNumber.Text(16))
	requiredSerial = strings.ReplaceAll(strings.ToUpper(requiredSerial), ":", "")
	if actualSerial != requiredSerial {
		return false, nil
	}
	return checkCA(p, cert)
}

func matchX509CN(p *models.Principal, cert *x509.Certificate) (bool, error) {
	requiredCN, ok := p.AuthConfig["subject_cn"].(string)
	if !ok {
		return false, fmt.Errorf("missing subject_cn in auth_config")
	}
	if strings.Contains(requiredCN, "*") {
		matched, _ := filepath.Match(requiredCN, cert.Subject.CommonName)
		if !matched {
			return false, nil
		}
	} else {
		if cert.Subject.CommonName != requiredCN {
			return false, nil
		}
	}
	return checkCA(p, cert)
}

type x509CATrustConfig struct {
	PEM          string
	IdentityType string
	Value        string
}

func checkCA(p *models.Principal, cert *x509.Certificate) (bool, error) {
	caTrust, err := getX509CATrustConfig(p.AuthConfig)
	if err != nil {
		return false, err
	}
	caCert, err := parseCATrustCertificate(caTrust.PEM)
	if err != nil {
		return false, err
	}
	if err := cert.CheckSignatureFrom(caCert); err != nil {
		return false, nil
	}
	switch caTrust.IdentityType {
	case "fingerprint":
		return matchCAFingerprint(caCert, caTrust.Value), nil
	case "authority_key_id":
		return matchCAAuthorityKeyID(cert, caCert, caTrust.Value), nil
	default:
		return false, fmt.Errorf("unsupported ca_trust.identity_type: %s", caTrust.IdentityType)
	}
}

func getX509CATrustConfig(authConfig map[string]interface{}) (*x509CATrustConfig, error) {
	caTrustRaw, ok := authConfig["ca_trust"]
	if !ok {
		return nil, fmt.Errorf("missing ca_trust in auth_config")
	}
	caTrustMap, ok := caTrustRaw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid ca_trust in auth_config")
	}
	identityType, ok := caTrustMap["identity_type"].(string)
	if !ok || identityType == "" {
		return nil, fmt.Errorf("missing ca_trust.identity_type in auth_config")
	}
	value, ok := caTrustMap["value"].(string)
	if !ok || value == "" {
		return nil, fmt.Errorf("missing ca_trust.value in auth_config")
	}
	pemValue, ok := caTrustMap["pem"].(string)
	if !ok || pemValue == "" {
		return nil, fmt.Errorf("missing ca_trust.pem in auth_config")
	}
	return &x509CATrustConfig{PEM: pemValue, IdentityType: identityType, Value: value}, nil
}

func parseCATrustCertificate(value string) (*x509.Certificate, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return nil, fmt.Errorf("empty ca_trust.pem")
	}
	var pemBytes []byte
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err == nil {
		pemBytes = decoded
	} else {
		pemBytes = []byte(raw)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("invalid ca_trust.pem: expected PEM certificate")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid ca_trust.pem certificate: %w", err)
	}
	if !caCert.IsCA {
		return nil, fmt.Errorf("ca_trust.pem certificate is not a CA certificate")
	}
	return caCert, nil
}

func matchCAFingerprint(caCert *x509.Certificate, requiredFingerprint string) bool {
	hash := sha256.Sum256(caCert.Raw)
	actualFingerprint := "SHA256:" + strings.ToUpper(hex.EncodeToString(hash[:]))
	return normalizeFingerprint(actualFingerprint) == normalizeFingerprint(requiredFingerprint)
}

func matchCAAuthorityKeyID(cert *x509.Certificate, caCert *x509.Certificate, requiredAKI string) bool {
	if len(cert.AuthorityKeyId) == 0 || len(caCert.SubjectKeyId) == 0 {
		return false
	}
	actualAKI := strings.ToUpper(hex.EncodeToString(cert.AuthorityKeyId))
	caSKI := strings.ToUpper(hex.EncodeToString(caCert.SubjectKeyId))
	normalizedRequired := normalizeAKI(requiredAKI)
	return actualAKI == normalizedRequired && caSKI == normalizedRequired
}

func normalizeFingerprint(value string) string {
	v := strings.TrimSpace(strings.ToUpper(value))
	v = strings.ReplaceAll(v, " ", "")
	v = strings.ReplaceAll(v, ":", "")
	v = strings.ReplaceAll(v, "SHA256", "")
	v = strings.TrimPrefix(v, "=")
	v = strings.TrimPrefix(v, "0X")
	return v
}

func normalizeAKI(value string) string {
	v := strings.TrimSpace(strings.ToUpper(value))
	v = strings.ReplaceAll(v, " ", "")
	v = strings.TrimPrefix(v, "0X")
	return v
}
