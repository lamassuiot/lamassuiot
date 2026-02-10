package x509engines

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
	"time"

	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
)

// TestApplyIssuanceProfileToTemplate_SubjectCNPreservation tests the CN preservation logic
// when HonorSubject is false. It validates that:
// 1. When profile subject has no CN, the original template CN is preserved
// 2. When profile subject has a CN, it overrides the original template CN
// 3. Other subject fields are always overridden from the profile
func TestApplyIssuanceProfileToTemplate_SubjectCNPreservation(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	engine := NewX509Engine(logger, []string{"va.example.com"}, nil)
	ctx := context.Background()
	now := time.Now()

	testCases := []struct {
		name         string
		templateCN   string
		templateOrg  string
		profileCN    string
		profileOrg   string
		honorSubject bool
		expectedCN   string
		expectedOrg  string
	}{
		{
			name:         "HonorSubject=false, profile CN empty - preserves original CN",
			templateCN:   "device-123",
			templateOrg:  "Original Org",
			profileCN:    "", // Empty CN in profile
			profileOrg:   "Profile Org",
			honorSubject: false,
			expectedCN:   "device-123",  // Original CN preserved
			expectedOrg:  "Profile Org", // Other fields from profile
		},
		{
			name:         "HonorSubject=false, profile CN set - overrides original CN",
			templateCN:   "device-123",
			templateOrg:  "Original Org",
			profileCN:    "profile-cn-override",
			profileOrg:   "Profile Org",
			honorSubject: false,
			expectedCN:   "profile-cn-override", // Profile CN overrides
			expectedOrg:  "Profile Org",
		},
		{
			name:         "HonorSubject=true - template values preserved",
			templateCN:   "device-456",
			templateOrg:  "Original Org",
			profileCN:    "should-not-apply",
			profileOrg:   "Should Not Apply",
			honorSubject: true,
			expectedCN:   "device-456",   // Template preserved
			expectedOrg:  "Original Org", // Template preserved
		},
		{
			name:         "HonorSubject=false, both CNs empty",
			templateCN:   "",
			templateOrg:  "Original Org",
			profileCN:    "",
			profileOrg:   "Profile Org",
			honorSubject: false,
			expectedCN:   "", // Both empty results in empty
			expectedOrg:  "Profile Org",
		},
		{
			name:         "HonorSubject=false, template CN empty, profile CN set",
			templateCN:   "",
			templateOrg:  "Original Org",
			profileCN:    "profile-cn",
			profileOrg:   "Profile Org",
			honorSubject: false,
			expectedCN:   "profile-cn", // Profile CN used
			expectedOrg:  "Profile Org",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create template with original values
			template := &x509.Certificate{
				Subject: chelpers.SubjectToPkixName(models.Subject{
					CommonName:   tc.templateCN,
					Organization: tc.templateOrg,
				}),
				NotBefore: now,
				NotAfter:  now.Add(time.Hour),
			}

			// Create profile
			profile := models.IssuanceProfile{
				Validity: models.Validity{
					Type:     models.Duration,
					Duration: models.TimeDuration(time.Hour),
				},
				HonorSubject: tc.honorSubject,
				Subject: models.Subject{
					CommonName:   tc.profileCN,
					Organization: tc.profileOrg,
				},
			}

			// Apply profile to template
			err := engine.applyIssuanceProfileToTemplate(ctx, template, profile, now)
			if err != nil {
				t.Fatalf("applyIssuanceProfileToTemplate failed: %v", err)
			}

			// Verify CN
			if template.Subject.CommonName != tc.expectedCN {
				t.Errorf("CommonName mismatch: got %q, want %q",
					template.Subject.CommonName, tc.expectedCN)
			}

			// Verify Organization
			if tc.honorSubject {
				// When honoring subject, template org should be preserved
				if len(template.Subject.Organization) > 0 {
					if template.Subject.Organization[0] != tc.expectedOrg {
						t.Errorf("Organization mismatch: got %q, want %q",
							template.Subject.Organization[0], tc.expectedOrg)
					}
				}
			} else {
				// When not honoring subject, profile org should be applied
				if len(template.Subject.Organization) > 0 {
					if template.Subject.Organization[0] != tc.expectedOrg {
						t.Errorf("Organization mismatch: got %q, want %q",
							template.Subject.Organization[0], tc.expectedOrg)
					}
				}
			}
		})
	}
}

// TestApplyIssuanceProfileToTemplate_SubjectFields tests that all subject fields
// are properly handled when HonorSubject is false
func TestApplyIssuanceProfileToTemplate_SubjectFields(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	engine := NewX509Engine(logger, []string{"va.example.com"}, nil)
	ctx := context.Background()
	now := time.Now()

	// Template with full subject
	template := &x509.Certificate{
		Subject: chelpers.SubjectToPkixName(models.Subject{
			CommonName:       "original-cn",
			Organization:     "Original Org",
			OrganizationUnit: "Original OU",
			Country:          "US",
			State:            "California",
			Locality:         "San Francisco",
		}),
		NotBefore: now,
		NotAfter:  now.Add(time.Hour),
	}

	// Profile with different subject but no CN
	profile := models.IssuanceProfile{
		Validity: models.Validity{
			Type:     models.Duration,
			Duration: models.TimeDuration(time.Hour),
		},
		HonorSubject: false,
		Subject: models.Subject{
			CommonName:       "", // Empty CN - should preserve original
			Organization:     "Profile Org",
			OrganizationUnit: "Profile OU",
			Country:          "ES",
			State:            "Gipuzkoa",
			Locality:         "Arrasate",
		},
	}

	err := engine.applyIssuanceProfileToTemplate(ctx, template, profile, now)
	if err != nil {
		t.Fatalf("applyIssuanceProfileToTemplate failed: %v", err)
	}

	// Verify CN is preserved
	if template.Subject.CommonName != "original-cn" {
		t.Errorf("CN not preserved: got %q, want %q",
			template.Subject.CommonName, "original-cn")
	}

	// Verify other fields are from profile
	if len(template.Subject.Organization) == 0 || template.Subject.Organization[0] != "Profile Org" {
		t.Errorf("Organization not overridden: got %v, want %q",
			template.Subject.Organization, "Profile Org")
	}
	if len(template.Subject.OrganizationalUnit) == 0 || template.Subject.OrganizationalUnit[0] != "Profile OU" {
		t.Errorf("OrganizationalUnit not overridden: got %v, want %q",
			template.Subject.OrganizationalUnit, "Profile OU")
	}
	if len(template.Subject.Country) == 0 || template.Subject.Country[0] != "ES" {
		t.Errorf("Country not overridden: got %v, want %q",
			template.Subject.Country, "ES")
	}
	if len(template.Subject.Province) == 0 || template.Subject.Province[0] != "Gipuzkoa" {
		t.Errorf("State not overridden: got %v, want %q",
			template.Subject.Province, "Gipuzkoa")
	}
	if len(template.Subject.Locality) == 0 || template.Subject.Locality[0] != "Arrasate" {
		t.Errorf("Locality not overridden: got %v, want %q",
			template.Subject.Locality, "Arrasate")
	}
}

// TestApplyIssuanceProfileToTemplate_SparseSubjectFields tests handling of CSRs with minimal subject fields.
// This simulates real-world scenarios where CSRs may only contain CN or a subset of fields.
func TestApplyIssuanceProfileToTemplate_SparseSubjectFields(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	engine := NewX509Engine(logger, []string{"va.example.com"}, nil)
	ctx := context.Background()
	now := time.Now()

	testCases := []struct {
		name             string
		templateSubject  models.Subject
		profileSubject   models.Subject
		honorSubject     bool
		expectedCN       string
		expectedOrg      string
		expectedOU       string
		expectedCountry  string
		expectedState    string
		expectedLocality string
	}{
		{
			name: "CSR with only CN - profile adds missing fields",
			templateSubject: models.Subject{
				CommonName: "device-abc-123",
				// No other fields in CSR
			},
			profileSubject: models.Subject{
				CommonName:       "", // Empty - should preserve CSR CN
				Organization:     "Acme Corp",
				OrganizationUnit: "IoT Devices",
				Country:          "US",
				State:            "California",
				Locality:         "San Francisco",
			},
			honorSubject:     false,
			expectedCN:       "device-abc-123", // Preserved from CSR
			expectedOrg:      "Acme Corp",
			expectedOU:       "IoT Devices",
			expectedCountry:  "US",
			expectedState:    "California",
			expectedLocality: "San Francisco",
		},
		{
			name: "CSR with only CN - profile overrides CN and adds fields",
			templateSubject: models.Subject{
				CommonName: "device-xyz-456",
			},
			profileSubject: models.Subject{
				CommonName:       "managed-device",
				Organization:     "Acme Corp",
				OrganizationUnit: "IoT Devices",
				Country:          "US",
			},
			honorSubject:     false,
			expectedCN:       "managed-device",
			expectedOrg:      "Acme Corp",
			expectedOU:       "IoT Devices",
			expectedCountry:  "US",
			expectedState:    "", // Profile doesn't have this
			expectedLocality: "",
		},
		{
			name: "CSR with CN and Org only - profile fills remaining fields",
			templateSubject: models.Subject{
				CommonName:   "sensor-001",
				Organization: "Original Org", // Will be overridden
			},
			profileSubject: models.Subject{
				CommonName:       "", // Empty - preserve CSR CN
				Organization:     "Profile Org",
				OrganizationUnit: "Sensors",
				Country:          "ES",
				State:            "Gipuzkoa",
			},
			honorSubject:     false,
			expectedCN:       "sensor-001",
			expectedOrg:      "Profile Org",
			expectedOU:       "Sensors",
			expectedCountry:  "ES",
			expectedState:    "Gipuzkoa",
			expectedLocality: "",
		},
		{
			name: "Empty CSR subject - profile provides all fields",
			templateSubject: models.Subject{
				// All fields empty
			},
			profileSubject: models.Subject{
				CommonName:       "default-device",
				Organization:     "Default Org",
				OrganizationUnit: "Default OU",
				Country:          "US",
			},
			honorSubject:     false,
			expectedCN:       "default-device",
			expectedOrg:      "Default Org",
			expectedOU:       "Default OU",
			expectedCountry:  "US",
			expectedState:    "",
			expectedLocality: "",
		},
		{
			name: "HonorSubject=true - sparse CSR fields preserved as-is",
			templateSubject: models.Subject{
				CommonName: "device-honor-001",
				Country:    "JP",
				// Other fields missing
			},
			profileSubject: models.Subject{
				CommonName:       "should-not-apply",
				Organization:     "Should Not Apply",
				OrganizationUnit: "Should Not Apply",
				Country:          "US",
				State:            "California",
				Locality:         "San Francisco",
			},
			honorSubject:     true,
			expectedCN:       "device-honor-001", // From CSR
			expectedOrg:      "",                 // Not in CSR, not added
			expectedOU:       "",
			expectedCountry:  "JP", // From CSR
			expectedState:    "",   // Not in CSR
			expectedLocality: "",
		},
		{
			name: "Profile with partial fields - only specified fields applied",
			templateSubject: models.Subject{
				CommonName:   "device-partial-001",
				Organization: "Original Org",
				State:        "Original State",
			},
			profileSubject: models.Subject{
				CommonName:   "", // Preserve CSR CN
				Organization: "New Org",
				// Country, State, Locality not specified in profile
			},
			honorSubject:     false,
			expectedCN:       "device-partial-001",
			expectedOrg:      "New Org",
			expectedOU:       "",
			expectedCountry:  "",
			expectedState:    "", // Profile doesn't have State
			expectedLocality: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create template from CSR-like subject (sparse fields)
			template := &x509.Certificate{
				Subject:   chelpers.SubjectToPkixName(tc.templateSubject),
				NotBefore: now,
				NotAfter:  now.Add(time.Hour),
			}

			// Create profile
			profile := models.IssuanceProfile{
				Validity: models.Validity{
					Type:     models.Duration,
					Duration: models.TimeDuration(time.Hour),
				},
				HonorSubject: tc.honorSubject,
				Subject:      tc.profileSubject,
			}

			// Apply profile to template
			err := engine.applyIssuanceProfileToTemplate(ctx, template, profile, now)
			if err != nil {
				t.Fatalf("applyIssuanceProfileToTemplate failed: %v", err)
			}

			// Verify CN
			if template.Subject.CommonName != tc.expectedCN {
				t.Errorf("CN mismatch: got %q, want %q",
					template.Subject.CommonName, tc.expectedCN)
			}

			// Verify Organization
			if tc.expectedOrg == "" {
				if len(template.Subject.Organization) > 0 && template.Subject.Organization[0] != "" {
					t.Errorf("Organization should be empty, got %q",
						template.Subject.Organization[0])
				}
			} else {
				if len(template.Subject.Organization) == 0 {
					t.Errorf("Organization missing, want %q", tc.expectedOrg)
				} else if template.Subject.Organization[0] != tc.expectedOrg {
					t.Errorf("Organization mismatch: got %q, want %q",
						template.Subject.Organization[0], tc.expectedOrg)
				}
			}

			// Verify OrganizationalUnit
			if tc.expectedOU == "" {
				if len(template.Subject.OrganizationalUnit) > 0 && template.Subject.OrganizationalUnit[0] != "" {
					t.Errorf("OrganizationalUnit should be empty, got %q",
						template.Subject.OrganizationalUnit[0])
				}
			} else {
				if len(template.Subject.OrganizationalUnit) == 0 {
					t.Errorf("OrganizationalUnit missing, want %q", tc.expectedOU)
				} else if template.Subject.OrganizationalUnit[0] != tc.expectedOU {
					t.Errorf("OrganizationalUnit mismatch: got %q, want %q",
						template.Subject.OrganizationalUnit[0], tc.expectedOU)
				}
			}

			// Verify Country
			if tc.expectedCountry == "" {
				if len(template.Subject.Country) > 0 && template.Subject.Country[0] != "" {
					t.Errorf("Country should be empty, got %q",
						template.Subject.Country[0])
				}
			} else {
				if len(template.Subject.Country) == 0 {
					t.Errorf("Country missing, want %q", tc.expectedCountry)
				} else if template.Subject.Country[0] != tc.expectedCountry {
					t.Errorf("Country mismatch: got %q, want %q",
						template.Subject.Country[0], tc.expectedCountry)
				}
			}

			// Verify State
			if tc.expectedState == "" {
				if len(template.Subject.Province) > 0 && template.Subject.Province[0] != "" {
					t.Errorf("State should be empty, got %q",
						template.Subject.Province[0])
				}
			} else {
				if len(template.Subject.Province) == 0 {
					t.Errorf("State missing, want %q", tc.expectedState)
				} else if template.Subject.Province[0] != tc.expectedState {
					t.Errorf("State mismatch: got %q, want %q",
						template.Subject.Province[0], tc.expectedState)
				}
			}

			// Verify Locality
			if tc.expectedLocality == "" {
				if len(template.Subject.Locality) > 0 && template.Subject.Locality[0] != "" {
					t.Errorf("Locality should be empty, got %q",
						template.Subject.Locality[0])
				}
			} else {
				if len(template.Subject.Locality) == 0 {
					t.Errorf("Locality missing, want %q", tc.expectedLocality)
				} else if template.Subject.Locality[0] != tc.expectedLocality {
					t.Errorf("Locality mismatch: got %q, want %q",
						template.Subject.Locality[0], tc.expectedLocality)
				}
			}
		})
	}
}

// TestApplyIssuanceProfileToTemplate_KeyUsage tests key usage handling
func TestApplyIssuanceProfileToTemplate_KeyUsage(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	engine := NewX509Engine(logger, []string{"va.example.com"}, nil)
	ctx := context.Background()
	now := time.Now()

	testCases := []struct {
		name          string
		templateKU    x509.KeyUsage
		profileKU     models.X509KeyUsage
		honorKeyUsage bool
		expectedKU    x509.KeyUsage
	}{
		{
			name:          "HonorKeyUsage=false - profile overrides",
			templateKU:    x509.KeyUsageDigitalSignature,
			profileKU:     models.X509KeyUsage(x509.KeyUsageKeyEncipherment),
			honorKeyUsage: false,
			expectedKU:    x509.KeyUsageKeyEncipherment,
		},
		{
			name:          "HonorKeyUsage=true - template preserved",
			templateKU:    x509.KeyUsageDigitalSignature,
			profileKU:     models.X509KeyUsage(x509.KeyUsageKeyEncipherment),
			honorKeyUsage: true,
			expectedKU:    x509.KeyUsageDigitalSignature,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			template := &x509.Certificate{
				Subject:   chelpers.SubjectToPkixName(models.Subject{CommonName: "test"}),
				KeyUsage:  tc.templateKU,
				NotBefore: now,
				NotAfter:  now.Add(time.Hour),
			}

			profile := models.IssuanceProfile{
				Validity: models.Validity{
					Type:     models.Duration,
					Duration: models.TimeDuration(time.Hour),
				},
				HonorKeyUsage: tc.honorKeyUsage,
				KeyUsage:      tc.profileKU,
			}

			err := engine.applyIssuanceProfileToTemplate(ctx, template, profile, now)
			if err != nil {
				t.Fatalf("applyIssuanceProfileToTemplate failed: %v", err)
			}

			if template.KeyUsage != tc.expectedKU {
				t.Errorf("KeyUsage mismatch: got %v, want %v",
					template.KeyUsage, tc.expectedKU)
			}
		})
	}
}

// TestApplyIssuanceProfileToTemplate_ExtendedKeyUsage tests extended key usage handling
func TestApplyIssuanceProfileToTemplate_ExtendedKeyUsage(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	engine := NewX509Engine(logger, []string{"va.example.com"}, nil)
	ctx := context.Background()
	now := time.Now()

	testCases := []struct {
		name                   string
		templateEKU            []x509.ExtKeyUsage
		profileEKU             []models.X509ExtKeyUsage
		honorExtendedKeyUsages bool
		expectedEKU            []x509.ExtKeyUsage
	}{
		{
			name:                   "HonorExtendedKeyUsages=false - profile overrides",
			templateEKU:            []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			profileEKU:             []models.X509ExtKeyUsage{models.X509ExtKeyUsage(x509.ExtKeyUsageClientAuth)},
			honorExtendedKeyUsages: false,
			expectedEKU:            []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		{
			name:                   "HonorExtendedKeyUsages=true - template preserved",
			templateEKU:            []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			profileEKU:             []models.X509ExtKeyUsage{models.X509ExtKeyUsage(x509.ExtKeyUsageClientAuth)},
			honorExtendedKeyUsages: true,
			expectedEKU:            []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			template := &x509.Certificate{
				Subject:     chelpers.SubjectToPkixName(models.Subject{CommonName: "test"}),
				ExtKeyUsage: tc.templateEKU,
				NotBefore:   now,
				NotAfter:    now.Add(time.Hour),
			}

			profile := models.IssuanceProfile{
				Validity: models.Validity{
					Type:     models.Duration,
					Duration: models.TimeDuration(time.Hour),
				},
				HonorExtendedKeyUsages: tc.honorExtendedKeyUsages,
				ExtendedKeyUsages:      tc.profileEKU,
			}

			err := engine.applyIssuanceProfileToTemplate(ctx, template, profile, now)
			if err != nil {
				t.Fatalf("applyIssuanceProfileToTemplate failed: %v", err)
			}

			if len(template.ExtKeyUsage) != len(tc.expectedEKU) {
				t.Errorf("ExtKeyUsage length mismatch: got %d, want %d",
					len(template.ExtKeyUsage), len(tc.expectedEKU))
			}

			for i, eku := range tc.expectedEKU {
				if i >= len(template.ExtKeyUsage) || template.ExtKeyUsage[i] != eku {
					t.Errorf("ExtKeyUsage[%d] mismatch: got %v, want %v",
						i, template.ExtKeyUsage, eku)
				}
			}
		})
	}
}

// TestApplyIssuanceProfileToTemplate_CAConstraints tests CA constraint handling
func TestApplyIssuanceProfileToTemplate_CAConstraints(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	engine := NewX509Engine(logger, []string{"va.example.com"}, nil)
	ctx := context.Background()
	now := time.Now()

	testCases := []struct {
		name       string
		signAsCA   bool
		expectedCA bool
	}{
		{
			name:       "SignAsCA=true - CA certificate",
			signAsCA:   true,
			expectedCA: true,
		},
		{
			name:       "SignAsCA=false - end entity certificate",
			signAsCA:   false,
			expectedCA: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			template := &x509.Certificate{
				Subject:   chelpers.SubjectToPkixName(models.Subject{CommonName: "test"}),
				NotBefore: now,
				NotAfter:  now.Add(time.Hour),
			}

			profile := models.IssuanceProfile{
				Validity: models.Validity{
					Type:     models.Duration,
					Duration: models.TimeDuration(time.Hour),
				},
				SignAsCA: tc.signAsCA,
			}

			err := engine.applyIssuanceProfileToTemplate(ctx, template, profile, now)
			if err != nil {
				t.Fatalf("applyIssuanceProfileToTemplate failed: %v", err)
			}

			if template.IsCA != tc.expectedCA {
				t.Errorf("IsCA mismatch: got %v, want %v",
					template.IsCA, tc.expectedCA)
			}

			if tc.signAsCA && !template.BasicConstraintsValid {
				t.Error("BasicConstraintsValid should be true for CA certificates")
			}
		})
	}
}

// TestValidateCryptoEnforcement tests the crypto enforcement validation
func TestValidateCryptoEnforcement(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	engine := NewX509Engine(logger, []string{"va.example.com"}, nil)
	ctx := context.Background()

	// Generate test keys
	rsaKey2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaKey4096, _ := rsa.GenerateKey(rand.Reader, 4096)
	ecdsaKey256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecdsaKey384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	testCases := []struct {
		name        string
		publicKey   interface{}
		enforcement models.IssuanceProfileCryptoEnforcement
		expectError bool
	}{
		{
			name:      "Enforcement disabled - accepts any key",
			publicKey: &rsaKey2048.PublicKey,
			enforcement: models.IssuanceProfileCryptoEnforcement{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name:      "RSA allowed, correct size",
			publicKey: &rsaKey2048.PublicKey,
			enforcement: models.IssuanceProfileCryptoEnforcement{
				Enabled:            true,
				AllowRSAKeys:       true,
				AllowedRSAKeySizes: []int{2048, 4096},
			},
			expectError: false,
		},
		{
			name:      "RSA not allowed",
			publicKey: &rsaKey2048.PublicKey,
			enforcement: models.IssuanceProfileCryptoEnforcement{
				Enabled:      true,
				AllowRSAKeys: false,
			},
			expectError: true,
		},
		{
			name:      "RSA wrong size",
			publicKey: &rsaKey2048.PublicKey,
			enforcement: models.IssuanceProfileCryptoEnforcement{
				Enabled:            true,
				AllowRSAKeys:       true,
				AllowedRSAKeySizes: []int{4096},
			},
			expectError: true,
		},
		{
			name:      "ECDSA allowed, correct size",
			publicKey: &ecdsaKey256.PublicKey,
			enforcement: models.IssuanceProfileCryptoEnforcement{
				Enabled:              true,
				AllowECDSAKeys:       true,
				AllowedECDSAKeySizes: []int{256, 384},
			},
			expectError: false,
		},
		{
			name:      "ECDSA not allowed",
			publicKey: &ecdsaKey256.PublicKey,
			enforcement: models.IssuanceProfileCryptoEnforcement{
				Enabled:        true,
				AllowECDSAKeys: false,
			},
			expectError: true,
		},
		{
			name:      "ECDSA wrong size",
			publicKey: &ecdsaKey384.PublicKey,
			enforcement: models.IssuanceProfileCryptoEnforcement{
				Enabled:              true,
				AllowECDSAKeys:       true,
				AllowedECDSAKeySizes: []int{256},
			},
			expectError: true,
		},
		{
			name:      "Mixed keys allowed - RSA 4096",
			publicKey: &rsaKey4096.PublicKey,
			enforcement: models.IssuanceProfileCryptoEnforcement{
				Enabled:              true,
				AllowRSAKeys:         true,
				AllowedRSAKeySizes:   []int{2048, 4096},
				AllowECDSAKeys:       true,
				AllowedECDSAKeySizes: []int{256, 384},
			},
			expectError: false,
		},
		{
			name:      "Mixed keys allowed - ECDSA 384",
			publicKey: &ecdsaKey384.PublicKey,
			enforcement: models.IssuanceProfileCryptoEnforcement{
				Enabled:              true,
				AllowRSAKeys:         true,
				AllowedRSAKeySizes:   []int{2048, 4096},
				AllowECDSAKeys:       true,
				AllowedECDSAKeySizes: []int{256, 384},
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := engine.validateCryptoEnforcement(ctx, tc.publicKey, tc.enforcement)

			if tc.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tc.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// TestApplyIssuanceProfileToTemplate_Validity tests validity period handling
func TestApplyIssuanceProfileToTemplate_Validity(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	engine := NewX509Engine(logger, []string{"va.example.com"}, nil)
	ctx := context.Background()
	now := time.Now()

	testCases := []struct {
		name             string
		validityType     models.ValidityType
		validityValue    interface{}
		expectedNotAfter time.Time
	}{
		{
			name:             "Duration based validity",
			validityType:     models.Duration,
			validityValue:    models.TimeDuration(24 * time.Hour),
			expectedNotAfter: now.Add(24 * time.Hour),
		},
		{
			name:             "Time based validity",
			validityType:     models.Time,
			validityValue:    now.Add(48 * time.Hour),
			expectedNotAfter: now.Add(48 * time.Hour),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			template := &x509.Certificate{
				Subject: chelpers.SubjectToPkixName(models.Subject{CommonName: "test"}),
			}

			profile := models.IssuanceProfile{}
			if tc.validityType == models.Duration {
				profile.Validity = models.Validity{
					Type:     models.Duration,
					Duration: tc.validityValue.(models.TimeDuration),
				}
			} else {
				profile.Validity = models.Validity{
					Type: models.Time,
					Time: tc.validityValue.(time.Time),
				}
			}

			err := engine.applyIssuanceProfileToTemplate(ctx, template, profile, now)
			if err != nil {
				t.Fatalf("applyIssuanceProfileToTemplate failed: %v", err)
			}

			if !template.NotBefore.Equal(now) {
				t.Errorf("NotBefore mismatch: got %v, want %v",
					template.NotBefore, now)
			}

			// Allow small time difference due to processing
			diff := template.NotAfter.Sub(tc.expectedNotAfter)
			if diff < 0 {
				diff = -diff
			}
			if diff > time.Second {
				t.Errorf("NotAfter mismatch: got %v, want %v (diff: %v)",
					template.NotAfter, tc.expectedNotAfter, diff)
			}
		})
	}
}
