package authz

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/lamassuiot/authz/pkg/models"
	"github.com/lamassuiot/authz/pkg/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gocloud.dev/blob"
	"gocloud.dev/blob/memblob"
)

func createTestCAAndLeafCerts(t *testing.T) (*x509.Certificate, *x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1001),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0x14, 0xAF, 0x9C, 0x22, 0x11, 0x8B, 0x7E, 0x4A},
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2002),
		Subject:               pkix.Name{CommonName: "sensor-001.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		AuthorityKeyId:        caCert.SubjectKeyId,
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	return caCert, leafCert, caKey
}

func sha256FingerprintFromDER(der []byte) string {
	h := sha256.Sum256(der)
	return "SHA256:" + hex.EncodeToString(h[:])
}

func formatAKIValue(aki []byte) string {
	return hex.EncodeToString(aki)
}

func base64PEMFromCert(cert *x509.Certificate) string {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return base64.StdEncoding.EncodeToString(certPEM)
}

func TestPrincipalManager_MatchX509_CNAndCA_AuthorityKeyID(t *testing.T) {
	caCert, leafCert, _ := createTestCAAndLeafCerts(t)

	pm := &PrincipalManager{}
	principal := &models.Principal{
		AuthConfig: map[string]interface{}{
			"match_mode": "cn_and_ca",
			"subject_cn": "sensor-*.example.com",
			"ca_trust": map[string]interface{}{
				"pem":           base64PEMFromCert(caCert),
				"identity_type": "authority_key_id",
				"value":         formatAKIValue(leafCert.AuthorityKeyId),
			},
		},
	}

	matched, err := pm.matchX509(principal, leafCert)
	require.NoError(t, err)
	assert.True(t, matched)
}

func TestPrincipalManager_MatchX509_AnyFromCA_FingerprintSelfSignedCA(t *testing.T) {
	caCert, _, _ := createTestCAAndLeafCerts(t)

	pm := &PrincipalManager{}
	principal := &models.Principal{
		AuthConfig: map[string]interface{}{
			"match_mode": "any_from_ca",
			"ca_trust": map[string]interface{}{
				"pem":           base64PEMFromCert(caCert),
				"identity_type": "fingerprint",
				"value":         sha256FingerprintFromDER(caCert.Raw),
			},
		},
	}

	matched, err := pm.matchX509(principal, caCert)
	require.NoError(t, err)
	assert.True(t, matched)
}

func TestPrincipalManager_MatchX509_AnyFromCA_MissingPEM(t *testing.T) {
	caCert, _, _ := createTestCAAndLeafCerts(t)

	pm := &PrincipalManager{}
	principal := &models.Principal{
		AuthConfig: map[string]interface{}{
			"match_mode": "any_from_ca",
			"ca_trust": map[string]interface{}{
				"identity_type": "fingerprint",
				"value":         sha256FingerprintFromDER(caCert.Raw),
			},
		},
	}

	matched, err := pm.matchX509(principal, caCert)
	require.Error(t, err)
	assert.False(t, matched)
	assert.Contains(t, err.Error(), "missing ca_trust.pem")
}

// setupTestBucket creates an in-memory blob bucket for testing
func setupTestBucket(t *testing.T) *blob.Bucket {
	return memblob.OpenBucket(nil)
}

func TestPrincipalManager_CreatePrincipal(t *testing.T) {
	container, err := testutil.RunPostgresWithMigration("../../examples/iot/migrations.sql")
	require.NoError(t, err)
	defer container.Cleanup()

	// Create bucket
	bucket := setupTestBucket(t)
	defer bucket.Close()

	// Create principal manager
	pm, err := NewPrincipalManager(container.DB, bucket)
	require.NoError(t, err)

	// Test creating a principal
	principal := &models.Principal{
		ID:          "user-1",
		Name:        "John Doe",
		Description: "Initial description",
		Active:      true,
	}

	err = pm.CreatePrincipal(principal)
	assert.NoError(t, err)

	// Verify it was created
	retrieved, err := pm.GetPrincipal("user-1")
	require.NoError(t, err)
	assert.Equal(t, "John Doe", retrieved.Name)
	assert.Equal(t, "Initial description", retrieved.Description)
	assert.True(t, retrieved.Active)
}

func TestPrincipalManager_UpdatePrincipalDescription(t *testing.T) {
	container, err := testutil.RunPostgresWithMigration("../../examples/iot/migrations.sql")
	require.NoError(t, err)
	defer container.Cleanup()

	bucket := setupTestBucket(t)
	defer bucket.Close()

	pm, err := NewPrincipalManager(container.DB, bucket)
	require.NoError(t, err)

	principal := &models.Principal{
		ID:          "user-1",
		Name:        "John Doe",
		Description: "Before update",
		Active:      true,
	}
	err = pm.CreatePrincipal(principal)
	require.NoError(t, err)

	principal.Description = "After update"
	err = pm.UpdatePrincipal(principal)
	require.NoError(t, err)

	retrieved, err := pm.GetPrincipal("user-1")
	require.NoError(t, err)
	assert.Equal(t, "After update", retrieved.Description)
}

func TestPrincipalManager_GrantPolicy(t *testing.T) {
	container, err := testutil.RunPostgresWithMigration("../../examples/iot/migrations.sql")
	require.NoError(t, err)
	defer container.Cleanup()

	// Create bucket
	bucket := setupTestBucket(t)
	defer bucket.Close()

	// Create principal manager
	pm, err := NewPrincipalManager(container.DB, bucket)
	require.NoError(t, err)

	// Create a principal
	principal := &models.Principal{
		ID:   "user-1",
		Name: "John Doe",
	}
	err = pm.CreatePrincipal(principal)
	require.NoError(t, err)

	// Grant a policy
	err = pm.GrantPolicy("user-1", "policy-iot-admin", "admin")
	assert.NoError(t, err)

	// Verify the grant
	hasPolicy, err := pm.HasPolicy("user-1", "policy-iot-admin")
	require.NoError(t, err)
	assert.True(t, hasPolicy)

	// Get policies
	policyIDs, err := pm.GetPrincipalPolicies("user-1")
	require.NoError(t, err)
	assert.Len(t, policyIDs, 1)
	assert.Equal(t, "policy-iot-admin", policyIDs[0])
}

func TestPrincipalManager_RevokePolicy(t *testing.T) {
	container, err := testutil.RunPostgresWithMigration("../../examples/iot/migrations.sql")
	require.NoError(t, err)
	defer container.Cleanup()

	// Create bucket
	bucket := setupTestBucket(t)
	defer bucket.Close()

	// Create principal manager
	pm, err := NewPrincipalManager(container.DB, bucket)
	require.NoError(t, err)

	// Create principal and grant policy
	principal := &models.Principal{
		ID:   "user-1",
		Name: "John Doe",
	}
	err = pm.CreatePrincipal(principal)
	require.NoError(t, err)

	err = pm.GrantPolicy("user-1", "policy-iot-admin", "admin")
	require.NoError(t, err)

	// Revoke the policy
	err = pm.RevokePolicy("user-1", "policy-iot-admin")
	assert.NoError(t, err)

	// Verify it was revoked
	hasPolicy, err := pm.HasPolicy("user-1", "policy-iot-admin")
	require.NoError(t, err)
	assert.False(t, hasPolicy)
}

func TestPrincipalManager_GrantMultiplePolicies(t *testing.T) {
	container, err := testutil.RunPostgresWithMigration("../../examples/iot/migrations.sql")
	require.NoError(t, err)
	defer container.Cleanup()

	// Create bucket
	bucket := setupTestBucket(t)
	defer bucket.Close()

	// Create principal manager
	pm, err := NewPrincipalManager(container.DB, bucket)
	require.NoError(t, err)

	// Create principal
	principal := &models.Principal{
		ID:   "user-1",
		Name: "John Doe",
	}
	err = pm.CreatePrincipal(principal)
	require.NoError(t, err)

	// Grant multiple policies (grant the same policy once - duplicate should be skipped)
	policyIDs := []string{"policy-iot-admin"}
	err = pm.GrantPolicies("user-1", policyIDs, "admin")
	assert.NoError(t, err)

	// Verify it was granted
	count, err := pm.CountPrincipalPolicies("user-1")
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
}

func TestPrincipalManager_GetPolicyPrincipals(t *testing.T) {
	container, err := testutil.RunPostgresWithMigration("../../examples/iot/migrations.sql")
	require.NoError(t, err)
	defer container.Cleanup()

	// Create bucket
	bucket := setupTestBucket(t)
	defer bucket.Close()

	// Create principal manager
	pm, err := NewPrincipalManager(container.DB, bucket)
	require.NoError(t, err)

	// Create multiple principals
	for i := 1; i <= 3; i++ {
		principal := &models.Principal{
			ID:   "user-" + string(rune('0'+i)),
			Name: "User " + string(rune('0'+i)),
		}
		err = pm.CreatePrincipal(principal)
		require.NoError(t, err)
	}

	// Grant the same policy to all principals
	for i := 1; i <= 3; i++ {
		err = pm.GrantPolicy("user-"+string(rune('0'+i)), "policy-iot-admin", "admin")
		require.NoError(t, err)
	}

	// Get all principals with this policy
	principals, err := pm.GetPolicyPrincipals("policy-iot-admin")
	require.NoError(t, err)
	assert.Len(t, principals, 3)

	// Count principals
	count, err := pm.CountPolicyPrincipals("policy-iot-admin")
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)
}

func TestPrincipalManager_DeletePrincipal(t *testing.T) {
	container, err := testutil.RunPostgresWithMigration("../../examples/iot/migrations.sql")
	require.NoError(t, err)
	defer container.Cleanup()

	// Create bucket
	bucket := setupTestBucket(t)
	defer bucket.Close()

	// Create principal manager
	pm, err := NewPrincipalManager(container.DB, bucket)
	require.NoError(t, err)

	// Create principal and grant policies
	principal := &models.Principal{
		ID:   "user-1",
		Name: "John Doe",
	}
	err = pm.CreatePrincipal(principal)
	require.NoError(t, err)

	err = pm.GrantPolicy("user-1", "policy-iot-admin", "admin")
	require.NoError(t, err)

	// Delete the principal
	err = pm.DeletePrincipal("user-1")
	assert.NoError(t, err)

	// Verify it was deleted
	_, err = pm.GetPrincipal("user-1")
	assert.Error(t, err)

	// Verify policy associations were also deleted
	count, err := pm.CountPrincipalPolicies("user-1")
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

func TestPrincipalManager_SetPrincipalActive(t *testing.T) {
	container, err := testutil.RunPostgresWithMigration("../../examples/iot/migrations.sql")
	require.NoError(t, err)
	defer container.Cleanup()

	// Create bucket
	bucket := setupTestBucket(t)
	defer bucket.Close()

	// Create principal manager
	pm, err := NewPrincipalManager(container.DB, bucket)
	require.NoError(t, err)

	// Create principal
	principal := &models.Principal{
		ID:     "user-1",
		Name:   "John Doe",
		Active: true,
	}
	err = pm.CreatePrincipal(principal)
	require.NoError(t, err)

	// Deactivate
	err = pm.SetPrincipalActive("user-1", false)
	assert.NoError(t, err)

	// Verify
	retrieved, err := pm.GetPrincipal("user-1")
	require.NoError(t, err)
	assert.False(t, retrieved.Active)

	// Reactivate
	err = pm.SetPrincipalActive("user-1", true)
	assert.NoError(t, err)

	retrieved, err = pm.GetPrincipal("user-1")
	require.NoError(t, err)
	assert.True(t, retrieved.Active)
}

func TestPrincipalManager_ListPrincipals(t *testing.T) {
	container, err := testutil.RunPostgresWithMigration("../../examples/iot/migrations.sql")
	require.NoError(t, err)
	defer container.Cleanup()

	// Create bucket
	bucket := setupTestBucket(t)
	defer bucket.Close()

	// Create principal manager
	pm, err := NewPrincipalManager(container.DB, bucket)
	require.NoError(t, err)

	// Create active principals
	for i := 1; i <= 3; i++ {
		principal := &models.Principal{
			ID:     "user-" + string(rune('0'+i)),
			Name:   "Active User " + string(rune('0'+i)),
			Active: true,
		}
		err = pm.CreatePrincipal(principal)
		require.NoError(t, err)
	}

	// Create inactive principal
	inactive := &models.Principal{
		ID:     "user-inactive",
		Name:   "Inactive User",
		Active: false,
	}
	err = pm.CreatePrincipal(inactive)
	require.NoError(t, err)

	// Explicitly set to inactive (since default might override)
	err = pm.SetPrincipalActive("user-inactive", false)
	require.NoError(t, err)

	// List all principals
	all, err := pm.ListPrincipals(false)
	require.NoError(t, err)
	assert.Len(t, all, 4)

	// List only active principals
	active, err := pm.ListPrincipals(true)
	require.NoError(t, err)
	assert.Len(t, active, 3)
}
