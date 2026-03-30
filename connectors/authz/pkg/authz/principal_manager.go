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
	"github.com/google/uuid"
	"github.com/lamassuiot/authz/pkg/models"
	"gocloud.dev/blob"
	"gorm.io/gorm"
)

// PrincipalManager manages principals and their policy associations
type PrincipalManager struct {
	db     *gorm.DB
	bucket *blob.Bucket
}

// NewPrincipalManager creates a new principal manager
func NewPrincipalManager(db *gorm.DB, bucket *blob.Bucket) (*PrincipalManager, error) {
	manager := &PrincipalManager{
		db:     db,
		bucket: bucket,
	}

	// Auto-migrate the database schema
	if err := manager.migrate(); err != nil {
		return nil, fmt.Errorf("failed to migrate principal tables: %w", err)
	}

	return manager, nil
}

// migrate creates or updates the database tables for principals
func (m *PrincipalManager) migrate() error {
	return m.db.AutoMigrate(&models.Principal{}, &models.PrincipalPolicy{})
}

// CreatePrincipal creates a new principal
func (m *PrincipalManager) CreatePrincipal(principal *models.Principal) error {
	if principal.ID == "" {
		principal.ID = uuid.New().String()
	}

	if principal.Name == "" {
		return fmt.Errorf("principal name is required")
	}

	result := m.db.Create(principal)
	if result.Error != nil {
		return fmt.Errorf("failed to create principal: %w", result.Error)
	}

	return nil
}

// GetPrincipal retrieves a principal by ID
func (m *PrincipalManager) GetPrincipal(principalID string) (*models.Principal, error) {
	var principal models.Principal
	result := m.db.First(&principal, "id = ?", principalID)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("principal not found: %s", principalID)
		}
		return nil, fmt.Errorf("failed to get principal: %w", result.Error)
	}

	return &principal, nil
}

// GetPrincipalWithPolicies retrieves a principal with all associated policies
func (m *PrincipalManager) GetPrincipalWithPolicies(principalID string) (*models.Principal, error) {
	var principal models.Principal
	result := m.db.Preload("Policies").First(&principal, "id = ?", principalID)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("principal not found: %s", principalID)
		}
		return nil, fmt.Errorf("failed to get principal with policies: %w", result.Error)
	}

	return &principal, nil
}

// ListPrincipals retrieves all principals
func (m *PrincipalManager) ListPrincipals(activeOnly bool) ([]*models.Principal, error) {
	var principals []*models.Principal
	query := m.db

	if activeOnly {
		query = query.Where("active = ?", true)
	}

	result := query.Find(&principals)
	if result.Error != nil {
		return nil, fmt.Errorf("failed to list principals: %w", result.Error)
	}

	return principals, nil
}

// UpdatePrincipal updates an existing principal
func (m *PrincipalManager) UpdatePrincipal(principal *models.Principal) error {
	result := m.db.Model(&models.Principal{}).Where("id = ?", principal.ID).Updates(principal)
	if result.Error != nil {
		return fmt.Errorf("failed to update principal: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("principal not found: %s", principal.ID)
	}

	return nil
}

// DeletePrincipal deletes a principal and all associated policy grants
func (m *PrincipalManager) DeletePrincipal(principalID string) error {
	return m.db.Transaction(func(tx *gorm.DB) error {
		// Delete all policy associations
		if err := tx.Where("principal_id = ?", principalID).Delete(&models.PrincipalPolicy{}).Error; err != nil {
			return fmt.Errorf("failed to delete principal policies: %w", err)
		}

		// Delete the principal
		result := tx.Delete(&models.Principal{}, "id = ?", principalID)
		if result.Error != nil {
			return fmt.Errorf("failed to delete principal: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			return fmt.Errorf("principal not found: %s", principalID)
		}

		return nil
	})
}

// GrantPolicy associates a policy with a principal
func (m *PrincipalManager) GrantPolicy(principalID, policyID, grantedBy string) error {
	// Verify principal exists
	if _, err := m.GetPrincipal(principalID); err != nil {
		return err
	}

	// Check if association already exists
	var existing models.PrincipalPolicy
	result := m.db.Where("principal_id = ? AND policy_id = ?", principalID, policyID).First(&existing)
	if result.Error == nil {
		return fmt.Errorf("policy %s already granted to principal %s", policyID, principalID)
	}
	if result.Error != gorm.ErrRecordNotFound {
		return fmt.Errorf("failed to check existing policy grant: %w", result.Error)
	}

	// Create association
	association := &models.PrincipalPolicy{
		PrincipalID: principalID,
		PolicyID:    policyID,
		GrantedBy:   grantedBy,
	}

	if err := m.db.Create(association).Error; err != nil {
		return fmt.Errorf("failed to grant policy: %w", err)
	}

	return nil
}

// RevokePolicy removes a policy association from a principal
func (m *PrincipalManager) RevokePolicy(principalID, policyID string) error {
	result := m.db.Where("principal_id = ? AND policy_id = ?", principalID, policyID).Delete(&models.PrincipalPolicy{})
	if result.Error != nil {
		return fmt.Errorf("failed to revoke policy: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("policy association not found for principal %s and policy %s", principalID, policyID)
	}

	return nil
}

// GetPrincipalPolicies retrieves all policy IDs associated with a principal
func (m *PrincipalManager) GetPrincipalPolicies(principalID string) ([]string, error) {
	var associations []models.PrincipalPolicy
	result := m.db.Where("principal_id = ?", principalID).Find(&associations)
	if result.Error != nil {
		return nil, fmt.Errorf("failed to get principal policies: %w", result.Error)
	}

	policyIDs := make([]string, len(associations))
	for i, assoc := range associations {
		policyIDs[i] = assoc.PolicyID
	}

	return policyIDs, nil
}

// GetPolicyPrincipals retrieves all principals associated with a specific policy
func (m *PrincipalManager) GetPolicyPrincipals(policyID string) ([]*models.Principal, error) {
	var associations []models.PrincipalPolicy
	result := m.db.Where("policy_id = ?", policyID).Find(&associations)
	if result.Error != nil {
		return nil, fmt.Errorf("failed to get policy principals: %w", result.Error)
	}

	principals := make([]*models.Principal, 0, len(associations))
	for _, assoc := range associations {
		principal, err := m.GetPrincipal(assoc.PrincipalID)
		if err != nil {
			// Log warning but continue - principal might have been deleted
			continue
		}
		principals = append(principals, principal)
	}

	return principals, nil
}

// HasPolicy checks if a principal has a specific policy granted
func (m *PrincipalManager) HasPolicy(principalID, policyID string) (bool, error) {
	var count int64
	result := m.db.Model(&models.PrincipalPolicy{}).
		Where("principal_id = ? AND policy_id = ?", principalID, policyID).
		Count(&count)

	if result.Error != nil {
		return false, fmt.Errorf("failed to check policy grant: %w", result.Error)
	}

	return count > 0, nil
}

// CountPrincipalPolicies returns the number of policies granted to a principal
func (m *PrincipalManager) CountPrincipalPolicies(principalID string) (int64, error) {
	var count int64
	result := m.db.Model(&models.PrincipalPolicy{}).Where("principal_id = ?", principalID).Count(&count)
	if result.Error != nil {
		return 0, fmt.Errorf("failed to count principal policies: %w", result.Error)
	}

	return count, nil
}

// CountPolicyPrincipals returns the number of principals that have a specific policy
func (m *PrincipalManager) CountPolicyPrincipals(policyID string) (int64, error) {
	var count int64
	result := m.db.Model(&models.PrincipalPolicy{}).Where("policy_id = ?", policyID).Count(&count)
	if result.Error != nil {
		return 0, fmt.Errorf("failed to count policy principals: %w", result.Error)
	}

	return count, nil
}

// GrantPolicies grants multiple policies to a principal in a single transaction
func (m *PrincipalManager) GrantPolicies(principalID string, policyIDs []string, grantedBy string) error {
	return m.db.Transaction(func(tx *gorm.DB) error {
		for _, policyID := range policyIDs {
			// Check if already exists
			var existing models.PrincipalPolicy
			result := tx.Where("principal_id = ? AND policy_id = ?", principalID, policyID).First(&existing)
			if result.Error == nil {
				// Already exists, skip
				continue
			}
			if result.Error != gorm.ErrRecordNotFound {
				return fmt.Errorf("failed to check existing policy grant: %w", result.Error)
			}

			// Create association
			association := &models.PrincipalPolicy{
				PrincipalID: principalID,
				PolicyID:    policyID,
				GrantedBy:   grantedBy,
			}

			if err := tx.Create(association).Error; err != nil {
				return fmt.Errorf("failed to grant policy %s: %w", policyID, err)
			}
		}

		return nil
	})
}

// RevokePolicies revokes multiple policies from a principal in a single transaction
func (m *PrincipalManager) RevokePolicies(principalID string, policyIDs []string) error {
	return m.db.Transaction(func(tx *gorm.DB) error {
		for _, policyID := range policyIDs {
			result := tx.Where("principal_id = ? AND policy_id = ?", principalID, policyID).Delete(&models.PrincipalPolicy{})
			if result.Error != nil {
				return fmt.Errorf("failed to revoke policy %s: %w", policyID, result.Error)
			}
		}

		return nil
	})
}

// SetPrincipalActive sets the active status of a principal
func (m *PrincipalManager) SetPrincipalActive(principalID string, active bool) error {
	result := m.db.Model(&models.Principal{}).Where("id = ?", principalID).Update("active", active)
	if result.Error != nil {
		return fmt.Errorf("failed to update principal status: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("principal not found: %s", principalID)
	}

	return nil
}

// MatchPrincipals matches authentication material to principals
func (m *PrincipalManager) MatchPrincipals(ctx context.Context, authMaterial interface{}, authType string) ([]string, error) {
	// Validate auth type
	if authType != "oidc" && authType != "x509" {
		return nil, fmt.Errorf("invalid auth type: %s", authType)
	}

	// Query all enabled principals of the specified type
	var principals []models.Principal
	result := m.db.Where("type = ? AND active = ?", authType, true).Find(&principals)
	if result.Error != nil {
		return nil, fmt.Errorf("failed to query principals: %w", result.Error)
	}

	// Match against each principal using type-specific logic
	matchedIDs := make([]string, 0)
	for _, principal := range principals {
		matched, err := m.matchPrincipal(&principal, authMaterial, authType)
		if err != nil {
			// Log error but continue checking other principals
			continue
		}
		if matched {
			matchedIDs = append(matchedIDs, principal.ID)
		}
	}

	return matchedIDs, nil
}

// matchPrincipal applies type-specific matching logic
func (m *PrincipalManager) matchPrincipal(principal *models.Principal, authMaterial interface{}, authType string) (bool, error) {
	switch authType {
	case "oidc":
		return m.matchOIDC(principal, authMaterial)
	case "x509":
		return m.matchX509(principal, authMaterial)
	default:
		return false, fmt.Errorf("unsupported auth type: %s", authType)
	}
}

// matchOIDC matches OIDC JWT authentication
func (m *PrincipalManager) matchOIDC(principal *models.Principal, authMaterial interface{}) (bool, error) {
	// authMaterial should be a parsed JWT token or claims map
	var claims jwt.MapClaims

	switch v := authMaterial.(type) {
	case jwt.MapClaims:
		claims = v
	case map[string]interface{}:
		claims = jwt.MapClaims(v)
	case string:
		// Parse JWT token string
		v = strings.TrimPrefix(v, "Bearer ")

		parser := jwt.NewParser()

		_, _, err := parser.ParseUnverified(v, &claims)
		if err != nil {
			return false, fmt.Errorf("failed to parse JWT token: %w", err)
		}

		if claims == nil {
			return false, fmt.Errorf("invalid JWT claims format")
		}
	default:
		return false, fmt.Errorf("invalid OIDC auth material format")
	}

	// Check all claim conditions (AND logic)
	claimConditions, ok := principal.AuthConfig["claims"].([]interface{})
	if !ok {
		return false, fmt.Errorf("missing or invalid claims in auth_config")
	}

	for _, conditionInterface := range claimConditions {
		condition, ok := conditionInterface.(map[string]interface{})
		if !ok {
			continue
		}

		claimName, _ := condition["claim"].(string)
		operator, _ := condition["operator"].(string)
		expectedValue := condition["value"]

		if !m.evaluateClaim(claims, claimName, operator, expectedValue) {
			return false, nil
		}
	}

	return true, nil
}

// getNestedClaim retrieves a claim value from nested JWT claims using dot notation
func (m *PrincipalManager) getNestedClaim(claims jwt.MapClaims, claimPath string) (interface{}, bool) {
	parts := strings.Split(claimPath, ".")

	var current interface{} = claims
	for _, part := range parts {
		var currentMap map[string]interface{}

		// Handle the type assertion carefully.
		// jwt.MapClaims and map[string]interface{} are different types in Go's type system
		switch v := current.(type) {
		case jwt.MapClaims:
			currentMap = v
		case map[string]interface{}:
			currentMap = v
		default:
			return nil, false
		}

		// Get the next level
		next, exists := currentMap[part]
		if !exists {
			return nil, false
		}
		current = next
	}

	return current, true
}

// evaluateClaim checks a single claim condition
func (m *PrincipalManager) evaluateClaim(claims jwt.MapClaims, claimName, operator string, expectedValue interface{}) bool {
	actualValue, exists := m.getNestedClaim(claims, claimName)
	if !exists {
		return false
	}

	switch operator {
	case "equals":
		return fmt.Sprintf("%v", actualValue) == fmt.Sprintf("%v", expectedValue)

	case "contains":
		// For array claims, check if value is in array
		if arr, ok := actualValue.([]interface{}); ok {
			expectedStr := fmt.Sprintf("%v", expectedValue)
			for _, item := range arr {
				if fmt.Sprintf("%v", item) == expectedStr {
					return true
				}
			}
			return false
		}
		// For string claims, check substring
		actualStr := fmt.Sprintf("%v", actualValue)
		expectedStr := fmt.Sprintf("%v", expectedValue)
		return strings.Contains(actualStr, expectedStr)

	case "matches":
		// TODO: Implement regex matching
		return false

	default:
		return false
	}
}

// matchX509 matches X.509 certificate authentication
func (m *PrincipalManager) matchX509(principal *models.Principal, authMaterial interface{}) (bool, error) {
	// authMaterial should be *x509.Certificate or certificate data
	var cert *x509.Certificate

	switch v := authMaterial.(type) {
	case *x509.Certificate:
		cert = v
	case string:
		// Parse PEM encoded certificate
		block, _ := pem.Decode([]byte(v))
		if block == nil {
			return false, fmt.Errorf("failed to decode PEM block")
		}

		parsedCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return false, fmt.Errorf("failed to parse certificate: %w", err)
		}
		cert = parsedCert
	default:
		return false, fmt.Errorf("invalid x509 auth material format")
	}

	// Get match mode
	matchMode, ok := principal.AuthConfig["match_mode"].(string)
	if !ok {
		return false, fmt.Errorf("missing match_mode in auth_config")
	}

	switch matchMode {
	case "serial_and_ca":
		return m.matchX509SerialAndCA(principal, cert)
	case "cn", "cn_and_ca":
		return m.matchX509CN(principal, cert)
	case "any_from_ca":
		return m.matchX509AnyFromCA(principal, cert)
	default:
		return false, fmt.Errorf("invalid match_mode: %s", matchMode)
	}
}

// matchX509SerialAndCA matches certificate by serial number and CA
func (m *PrincipalManager) matchX509SerialAndCA(principal *models.Principal, cert *x509.Certificate) (bool, error) {
	requiredSerial, ok := principal.AuthConfig["serial_number"].(string)
	if !ok {
		return false, fmt.Errorf("missing serial_number in auth_config")
	}

	// Compare serial number (hex format)
	actualSerial := cert.SerialNumber.Text(16)
	actualSerial = strings.ToUpper(actualSerial)
	requiredSerial = strings.ReplaceAll(strings.ToUpper(requiredSerial), ":", "")

	if actualSerial != requiredSerial {
		return false, nil
	}

	// Check CA
	return m.checkCA(principal, cert)
}

// matchX509CN matches certificate by Common Name and CA
func (m *PrincipalManager) matchX509CN(principal *models.Principal, cert *x509.Certificate) (bool, error) {
	requiredCN, ok := principal.AuthConfig["subject_cn"].(string)
	if !ok {
		return false, fmt.Errorf("missing subject_cn in auth_config")
	}

	// Support wildcards
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

	// Check CA (CN mode also requires CA validation)
	return m.checkCA(principal, cert)
}

// matchX509AnyFromCA matches any certificate from specific CA
func (m *PrincipalManager) matchX509AnyFromCA(principal *models.Principal, cert *x509.Certificate) (bool, error) {
	return m.checkCA(principal, cert)
}

type x509CATrustConfig struct {
	PEM          string
	IdentityType string
	Value        string
}

// checkCA verifies the certificate against configured CA trust data.
func (m *PrincipalManager) checkCA(principal *models.Principal, cert *x509.Certificate) (bool, error) {
	caTrust, err := getX509CATrustConfig(principal.AuthConfig)
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
	if caTrustRaw, ok := authConfig["ca_trust"]; ok {
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

	return nil, fmt.Errorf("missing ca_trust in auth_config")
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
