package assemblers

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func TestEditCAProfiles(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	caDur := models.TimeDuration(time.Hour * 24)
	issuanceDur := models.TimeDuration(time.Hour * 12)

	// Helper function to create an issuance profile
	createProfile := func(t *testing.T, name, description string, validity models.Validity) *models.IssuanceProfile {
		profile, err := serverTest.CA.Service.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
			Profile: models.IssuanceProfile{
				Name:                   name,
				Description:            description,
				Validity:               validity,
				HonorKeyUsage:          true,
				KeyUsage:               models.X509KeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment),
				HonorExtendedKeyUsages: true,
				ExtendedKeyUsages: []models.X509ExtKeyUsage{
					models.X509ExtKeyUsage(x509.ExtKeyUsageServerAuth),
					models.X509ExtKeyUsage(x509.ExtKeyUsageClientAuth),
				},
			},
		})
		if err != nil {
			t.Fatalf("failed creating issuance profile: %s", err)
		}
		return profile
	}

	// Helper function to create a CA
	createCA := func(t *testing.T, caID string, profileID string) *models.CACertificate {
		ca, err := serverTest.CA.Service.CreateCA(context.Background(), services.CreateCAInput{
			ID:           caID,
			KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
			Subject:      models.Subject{CommonName: "TestCA"},
			CAExpiration: models.Validity{Type: models.Duration, Duration: caDur},
			ProfileID:    profileID,
		})
		if err != nil {
			t.Fatalf("failed creating CA: %s", err)
		}
		return ca
	}

	var testcases = []struct {
		name        string
		before      func(svc services.CAService) (string, string, error) // returns (caID, newProfileID, error)
		run         func(caSDK services.CAService, caID, newProfileID string) (*models.CACertificate, error)
		resultCheck func(originalCA *models.CACertificate, updatedCA *models.CACertificate, newProfileID string, err error) error
	}{
		{
			name: "OK/UpdateCAProfile-ValidProfile",
			before: func(svc services.CAService) (string, string, error) {
				// Create initial profile
				initialProfile := createProfile(t, "InitialProfile", "Initial profile description", models.Validity{Type: models.Duration, Duration: issuanceDur})

				// Create CA with initial profile
				ca := createCA(t, "test-ca-1", initialProfile.ID)

				// Create new profile to switch to
				newProfile := createProfile(t, "NewProfile", "New profile description", models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour * 6)})

				return ca.ID, newProfile.ID, nil
			},
			run: func(caSDK services.CAService, caID, newProfileID string) (*models.CACertificate, error) {
				return caSDK.UpdateCAProfile(context.Background(), services.UpdateCAProfileInput{
					CAID:      caID,
					ProfileID: newProfileID,
				})
			},
			resultCheck: func(originalCA *models.CACertificate, updatedCA *models.CACertificate, newProfileID string, err error) error {
				if err != nil {
					return fmt.Errorf("should've updated CA profile without error, but got error: %s", err)
				}

				if updatedCA.ProfileID != newProfileID {
					return fmt.Errorf("expected CA profile ID to be %s, but got %s", newProfileID, updatedCA.ProfileID)
				}

				if originalCA.ProfileID == updatedCA.ProfileID {
					return fmt.Errorf("CA profile ID should have changed, but it remained the same: %s", updatedCA.ProfileID)
				}

				// Verify other CA properties remain unchanged
				if updatedCA.ID != originalCA.ID {
					return fmt.Errorf("CA ID should not change during profile update")
				}

				if updatedCA.Certificate.Subject.CommonName != originalCA.Certificate.Subject.CommonName {
					return fmt.Errorf("CA subject should not change during profile update")
				}

				return nil
			},
		},
		{
			name: "Error/UpdateCAProfile-NonexistentCA",
			before: func(svc services.CAService) (string, string, error) {
				// Create a profile but no CA
				newProfile := createProfile(t, "TestProfile", "Test profile description", models.Validity{Type: models.Duration, Duration: issuanceDur})
				return "nonexistent-ca-id", newProfile.ID, nil
			},
			run: func(caSDK services.CAService, caID, newProfileID string) (*models.CACertificate, error) {
				return caSDK.UpdateCAProfile(context.Background(), services.UpdateCAProfileInput{
					CAID:      caID,
					ProfileID: newProfileID,
				})
			},
			resultCheck: func(originalCA *models.CACertificate, updatedCA *models.CACertificate, newProfileID string, err error) error {
				if err == nil {
					return fmt.Errorf("should've got error for nonexistent CA. Got none")
				}

				if !errors.Is(err, errs.ErrCANotFound) {
					return fmt.Errorf("should've got error %s. Got: %s", errs.ErrCANotFound, err)
				}

				return nil
			},
		},
		{
			name: "OK/UpdateCAProfile-SameProfile",
			before: func(svc services.CAService) (string, string, error) {
				// Create profile
				profile := createProfile(t, "SameProfile", "Same profile description", models.Validity{Type: models.Duration, Duration: issuanceDur})

				// Create CA with profile
				ca := createCA(t, "test-ca-2", profile.ID)

				// Return same profile ID for update
				return ca.ID, profile.ID, nil
			},
			run: func(caSDK services.CAService, caID, newProfileID string) (*models.CACertificate, error) {
				return caSDK.UpdateCAProfile(context.Background(), services.UpdateCAProfileInput{
					CAID:      caID,
					ProfileID: newProfileID,
				})
			},
			resultCheck: func(originalCA *models.CACertificate, updatedCA *models.CACertificate, newProfileID string, err error) error {
				if err != nil {
					return fmt.Errorf("should've updated CA profile without error, but got error: %s", err)
				}

				if updatedCA.ProfileID != newProfileID {
					return fmt.Errorf("expected CA profile ID to remain %s, but got %s", newProfileID, updatedCA.ProfileID)
				}

				if originalCA.ProfileID != updatedCA.ProfileID {
					return fmt.Errorf("CA profile ID should have remained the same: expected %s, got %s", originalCA.ProfileID, updatedCA.ProfileID)
				}

				return nil
			},
		},
		{
			name: "OK/UpdateCAProfile-DifferentValidityTypes",
			before: func(svc services.CAService) (string, string, error) {
				// Create initial profile with duration validity
				initialProfile := createProfile(t, "DurationProfile", "Duration-based profile", models.Validity{Type: models.Duration, Duration: issuanceDur})

				// Create CA with initial profile
				ca := createCA(t, "test-ca-3", initialProfile.ID)

				// Create new profile with time validity
				futureTime := time.Now().Add(time.Hour * 48)
				newProfile := createProfile(t, "TimeProfile", "Time-based profile", models.Validity{Type: models.Time, Time: futureTime})

				return ca.ID, newProfile.ID, nil
			},
			run: func(caSDK services.CAService, caID, newProfileID string) (*models.CACertificate, error) {
				return caSDK.UpdateCAProfile(context.Background(), services.UpdateCAProfileInput{
					CAID:      caID,
					ProfileID: newProfileID,
				})
			},
			resultCheck: func(originalCA *models.CACertificate, updatedCA *models.CACertificate, newProfileID string, err error) error {
				if err != nil {
					return fmt.Errorf("should've updated CA profile without error, but got error: %s", err)
				}

				if updatedCA.ProfileID != newProfileID {
					return fmt.Errorf("expected CA profile ID to be %s, but got %s", newProfileID, updatedCA.ProfileID)
				}

				return nil
			},
		},
		{
			name: "OK/UpdateCAProfile-MultipleConsecutiveUpdates",
			before: func(svc services.CAService) (string, string, error) {
				// Create multiple profiles
				profile1 := createProfile(t, "Profile1", "First profile", models.Validity{Type: models.Duration, Duration: issuanceDur})
				profile2 := createProfile(t, "Profile2", "Second profile", models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour * 8)})
				profile3 := createProfile(t, "Profile3", "Third profile", models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour * 4)})

				// Create CA with first profile
				ca := createCA(t, "test-ca-4", profile1.ID)

				// Update to second profile
				_, err := serverTest.CA.Service.UpdateCAProfile(context.Background(), services.UpdateCAProfileInput{
					CAID:      ca.ID,
					ProfileID: profile2.ID,
				})
				if err != nil {
					return "", "", fmt.Errorf("failed to update to second profile: %s", err)
				}

				// Return CA ID and third profile ID for final update
				return ca.ID, profile3.ID, nil
			},
			run: func(caSDK services.CAService, caID, newProfileID string) (*models.CACertificate, error) {
				return caSDK.UpdateCAProfile(context.Background(), services.UpdateCAProfileInput{
					CAID:      caID,
					ProfileID: newProfileID,
				})
			},
			resultCheck: func(originalCA *models.CACertificate, updatedCA *models.CACertificate, newProfileID string, err error) error {
				if err != nil {
					return fmt.Errorf("should've updated CA profile without error, but got error: %s", err)
				}

				if updatedCA.ProfileID != newProfileID {
					return fmt.Errorf("expected CA profile ID to be %s, but got %s", newProfileID, updatedCA.ProfileID)
				}

				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			err = serverTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' func in test case: %s", err)
			}

			caID, newProfileID, err := tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			// Get original CA state (only if CA exists)
			var originalCA *models.CACertificate
			if caID != "nonexistent-ca-id" { // Skip for test cases with nonexistent CA
				originalCA, err = caTest.Service.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: caID})
				if err != nil {
					t.Fatalf("failed to get original CA state: %s", err)
				}
			}

			updatedCA, err := tc.run(caTest.HttpCASDK, caID, newProfileID)

			err = tc.resultCheck(originalCA, updatedCA, newProfileID, err)
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

func TestEditIssuanceProfilesIntegration(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	issuanceDur := models.TimeDuration(time.Hour * 12)

	var testcases = []struct {
		name        string
		before      func(svc services.CAService) (*models.IssuanceProfile, error)
		run         func(caSDK services.CAService, profile *models.IssuanceProfile) (*models.IssuanceProfile, error)
		resultCheck func(originalProfile *models.IssuanceProfile, updatedProfile *models.IssuanceProfile, err error) error
	}{
		{
			name: "OK/UpdateIssuanceProfile-BasicFields",
			before: func(svc services.CAService) (*models.IssuanceProfile, error) {
				return svc.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Name:        "OriginalProfile",
						Description: "Original description",
						Validity:    models.Validity{Type: models.Duration, Duration: issuanceDur},
					},
				})
			},
			run: func(caSDK services.CAService, profile *models.IssuanceProfile) (*models.IssuanceProfile, error) {
				// Make a copy to avoid modifying the original
				updatedProfile := *profile
				updatedProfile.Name = "UpdatedProfile"
				updatedProfile.Description = "Updated description"
				updatedProfile.Validity = models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour * 6)}

				return caSDK.UpdateIssuanceProfile(context.Background(), services.UpdateIssuanceProfileInput{
					Profile: updatedProfile,
				})
			},
			resultCheck: func(originalProfile *models.IssuanceProfile, updatedProfile *models.IssuanceProfile, err error) error {
				if err != nil {
					return fmt.Errorf("should've updated issuance profile without error, but got error: %s", err)
				}

				if updatedProfile.Name != "UpdatedProfile" {
					return fmt.Errorf("expected profile name to be 'UpdatedProfile', but got '%s'", updatedProfile.Name)
				}

				if updatedProfile.Description != "Updated description" {
					return fmt.Errorf("expected profile description to be 'Updated description', but got '%s'", updatedProfile.Description)
				}

				if updatedProfile.ID != originalProfile.ID {
					return fmt.Errorf("profile ID should not change during update")
				}

				expectedDuration := models.TimeDuration(time.Hour * 6)
				if updatedProfile.Validity.Duration != expectedDuration {
					return fmt.Errorf("expected validity duration to be %d, but got %d", expectedDuration, updatedProfile.Validity.Duration)
				}

				return nil
			},
		},
		{
			name: "OK/UpdateIssuanceProfile-KeyUsageSettings",
			before: func(svc services.CAService) (*models.IssuanceProfile, error) {
				return svc.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Name:                   "KeyUsageProfile",
						Description:            "Profile for key usage testing",
						Validity:               models.Validity{Type: models.Duration, Duration: issuanceDur},
						HonorKeyUsage:          false,
						KeyUsage:               models.X509KeyUsage(x509.KeyUsageDigitalSignature),
						HonorExtendedKeyUsages: false,
						ExtendedKeyUsages:      []models.X509ExtKeyUsage{models.X509ExtKeyUsage(x509.ExtKeyUsageServerAuth)},
					},
				})
			},
			run: func(caSDK services.CAService, profile *models.IssuanceProfile) (*models.IssuanceProfile, error) {
				// Make a copy to avoid modifying the original
				updatedProfile := *profile
				updatedProfile.HonorKeyUsage = true
				updatedProfile.KeyUsage = models.X509KeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment)
				updatedProfile.HonorExtendedKeyUsages = true
				updatedProfile.ExtendedKeyUsages = []models.X509ExtKeyUsage{
					models.X509ExtKeyUsage(x509.ExtKeyUsageServerAuth),
					models.X509ExtKeyUsage(x509.ExtKeyUsageClientAuth),
				}

				return caSDK.UpdateIssuanceProfile(context.Background(), services.UpdateIssuanceProfileInput{
					Profile: updatedProfile,
				})
			},
			resultCheck: func(originalProfile *models.IssuanceProfile, updatedProfile *models.IssuanceProfile, err error) error {
				if err != nil {
					return fmt.Errorf("should've updated issuance profile without error, but got error: %s", err)
				}

				if !updatedProfile.HonorKeyUsage {
					return fmt.Errorf("expected HonorKeyUsage to be true")
				}

				if !updatedProfile.HonorExtendedKeyUsages {
					return fmt.Errorf("expected HonorExtendedKeyUsages to be true")
				}

				expectedKeyUsage := models.X509KeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment)
				if updatedProfile.KeyUsage != expectedKeyUsage {
					return fmt.Errorf("expected key usage to be %d, but got %d", expectedKeyUsage, updatedProfile.KeyUsage)
				}

				if len(updatedProfile.ExtendedKeyUsages) != 2 {
					return fmt.Errorf("expected 2 extended key usages, but got %d", len(updatedProfile.ExtendedKeyUsages))
				}

				return nil
			},
		},
		{
			name: "OK/UpdateIssuanceProfile-SignAsSetting",
			before: func(svc services.CAService) (*models.IssuanceProfile, error) {
				return svc.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Name:        "CAProfile",
						Description: "Profile for CA signing",
						Validity:    models.Validity{Type: models.Duration, Duration: issuanceDur},
						SignAsCA:    false,
					},
				})
			},
			run: func(caSDK services.CAService, profile *models.IssuanceProfile) (*models.IssuanceProfile, error) {
				// Make a copy to avoid modifying the original
				updatedProfile := *profile
				updatedProfile.SignAsCA = true
				updatedProfile.Description = "Updated to sign as CA"

				return caSDK.UpdateIssuanceProfile(context.Background(), services.UpdateIssuanceProfileInput{
					Profile: updatedProfile,
				})
			},
			resultCheck: func(originalProfile *models.IssuanceProfile, updatedProfile *models.IssuanceProfile, err error) error {
				if err != nil {
					return fmt.Errorf("should've updated issuance profile without error, but got error: %s", err)
				}

				if !updatedProfile.SignAsCA {
					return fmt.Errorf("expected SignAsCA to be true")
				}

				if originalProfile.SignAsCA {
					return fmt.Errorf("original profile should not have been SignAsCA")
				}

				return nil
			},
		},
		{
			name: "OK/UpdateIssuanceProfile-ValidityTypeChange",
			before: func(svc services.CAService) (*models.IssuanceProfile, error) {
				return svc.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Name:        "ValidityProfile",
						Description: "Profile for validity testing",
						Validity:    models.Validity{Type: models.Duration, Duration: issuanceDur},
					},
				})
			},
			run: func(caSDK services.CAService, profile *models.IssuanceProfile) (*models.IssuanceProfile, error) {
				// Make a copy to avoid modifying the original
				updatedProfile := *profile
				futureTime := time.Now().Add(time.Hour * 48)
				updatedProfile.Validity = models.Validity{Type: models.Time, Time: futureTime}

				return caSDK.UpdateIssuanceProfile(context.Background(), services.UpdateIssuanceProfileInput{
					Profile: updatedProfile,
				})
			},
			resultCheck: func(originalProfile *models.IssuanceProfile, updatedProfile *models.IssuanceProfile, err error) error {
				if err != nil {
					return fmt.Errorf("should've updated issuance profile without error, but got error: %s", err)
				}

				if updatedProfile.Validity.Type != models.Time {
					return fmt.Errorf("expected validity type to be Time, but got %s", updatedProfile.Validity.Type)
				}

				if originalProfile.Validity.Type != models.Duration {
					return fmt.Errorf("original validity type should have been Duration")
				}

				return nil
			},
		},
		{
			name: "OK/UpdateIssuanceProfile-ChangeKeyUsageAndExtendedKeyUsage",
			before: func(svc services.CAService) (*models.IssuanceProfile, error) {
				return svc.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Name:                   "KeyUsageChangeProfile",
						Description:            "Profile for testing key usage changes",
						Validity:               models.Validity{Type: models.Duration, Duration: issuanceDur},
						HonorKeyUsage:          true,
						KeyUsage:               models.X509KeyUsage(x509.KeyUsageDigitalSignature),
						HonorExtendedKeyUsages: true,
						ExtendedKeyUsages:      []models.X509ExtKeyUsage{models.X509ExtKeyUsage(x509.ExtKeyUsageServerAuth)},
					},
				})
			},
			run: func(caSDK services.CAService, profile *models.IssuanceProfile) (*models.IssuanceProfile, error) {
				// Make a copy to avoid modifying the original
				updatedProfile := *profile
				// Change key usage to include multiple usages
				updatedProfile.KeyUsage = models.X509KeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment)
				// Change extended key usages to include different ones
				updatedProfile.ExtendedKeyUsages = []models.X509ExtKeyUsage{
					models.X509ExtKeyUsage(x509.ExtKeyUsageClientAuth),
					models.X509ExtKeyUsage(x509.ExtKeyUsageCodeSigning),
					models.X509ExtKeyUsage(x509.ExtKeyUsageEmailProtection),
				}

				return caSDK.UpdateIssuanceProfile(context.Background(), services.UpdateIssuanceProfileInput{
					Profile: updatedProfile,
				})
			},
			resultCheck: func(originalProfile *models.IssuanceProfile, updatedProfile *models.IssuanceProfile, err error) error {
				if err != nil {
					return fmt.Errorf("should've updated issuance profile without error, but got error: %s", err)
				}

				// Verify key usage changed
				expectedKeyUsage := models.X509KeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment)
				if updatedProfile.KeyUsage != expectedKeyUsage {
					return fmt.Errorf("expected key usage to be %d, but got %d", expectedKeyUsage, updatedProfile.KeyUsage)
				}

				// Verify original key usage was different
				originalKeyUsage := models.X509KeyUsage(x509.KeyUsageDigitalSignature)
				if originalProfile.KeyUsage != originalKeyUsage {
					return fmt.Errorf("original key usage should have been %d, but was %d", originalKeyUsage, originalProfile.KeyUsage)
				}

				// Verify extended key usages changed
				if len(updatedProfile.ExtendedKeyUsages) != 3 {
					return fmt.Errorf("expected 3 extended key usages, but got %d", len(updatedProfile.ExtendedKeyUsages))
				}

				// Check specific extended key usages
				expectedExtKeyUsages := []models.X509ExtKeyUsage{
					models.X509ExtKeyUsage(x509.ExtKeyUsageClientAuth),
					models.X509ExtKeyUsage(x509.ExtKeyUsageCodeSigning),
					models.X509ExtKeyUsage(x509.ExtKeyUsageEmailProtection),
				}

				for i, expected := range expectedExtKeyUsages {
					if updatedProfile.ExtendedKeyUsages[i] != expected {
						return fmt.Errorf("expected extended key usage at index %d to be %d, but got %d", i, expected, updatedProfile.ExtendedKeyUsages[i])
					}
				}

				// Verify original extended key usage was different
				if len(originalProfile.ExtendedKeyUsages) != 1 {
					return fmt.Errorf("original profile should have had 1 extended key usage, but had %d", len(originalProfile.ExtendedKeyUsages))
				}

				if originalProfile.ExtendedKeyUsages[0] != models.X509ExtKeyUsage(x509.ExtKeyUsageServerAuth) {
					return fmt.Errorf("original extended key usage should have been ServerAuth")
				}

				return nil
			},
		},
		{
			name: "OK/UpdateIssuanceProfile-DisableKeyUsageHonoring",
			before: func(svc services.CAService) (*models.IssuanceProfile, error) {
				return svc.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Name:                   "DisableKeyUsageProfile",
						Description:            "Profile for testing disabling key usage honoring",
						Validity:               models.Validity{Type: models.Duration, Duration: issuanceDur},
						HonorKeyUsage:          true,
						KeyUsage:               models.X509KeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment),
						HonorExtendedKeyUsages: true,
						ExtendedKeyUsages: []models.X509ExtKeyUsage{
							models.X509ExtKeyUsage(x509.ExtKeyUsageServerAuth),
							models.X509ExtKeyUsage(x509.ExtKeyUsageClientAuth),
						},
					},
				})
			},
			run: func(caSDK services.CAService, profile *models.IssuanceProfile) (*models.IssuanceProfile, error) {
				// Make a copy to avoid modifying the original
				updatedProfile := *profile
				// Disable honoring of key usages
				updatedProfile.HonorKeyUsage = false
				updatedProfile.HonorExtendedKeyUsages = false

				return caSDK.UpdateIssuanceProfile(context.Background(), services.UpdateIssuanceProfileInput{
					Profile: updatedProfile,
				})
			},
			resultCheck: func(originalProfile *models.IssuanceProfile, updatedProfile *models.IssuanceProfile, err error) error {
				if err != nil {
					return fmt.Errorf("should've updated issuance profile without error, but got error: %s", err)
				}

				// Verify key usage honoring is disabled
				if updatedProfile.HonorKeyUsage {
					return fmt.Errorf("expected HonorKeyUsage to be false")
				}

				if updatedProfile.HonorExtendedKeyUsages {
					return fmt.Errorf("expected HonorExtendedKeyUsages to be false")
				}

				// Verify original had honoring enabled
				if !originalProfile.HonorKeyUsage {
					return fmt.Errorf("original profile should have had HonorKeyUsage enabled")
				}

				if !originalProfile.HonorExtendedKeyUsages {
					return fmt.Errorf("original profile should have had HonorExtendedKeyUsages enabled")
				}

				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			err = serverTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' func in test case: %s", err)
			}

			originalProfile, err := tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			updatedProfile, err := tc.run(caTest.HttpCASDK, originalProfile)

			err = tc.resultCheck(originalProfile, updatedProfile, err)
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

func TestEditCAProfilesWithCertificateImpacts(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	var testcases = []struct {
		name        string
		before      func(svc services.CAService) (string, string, string, error) // returns (caID, originalProfileID, newProfileID, error)
		run         func(caSDK services.CAService, caID, originalProfileID, newProfileID string) (*models.Certificate, error)
		resultCheck func(cert *models.Certificate, caID, originalProfileID, newProfileID string, err error) error
	}{
		{
			name: "OK/SignCertificateAfterProfileUpdate",
			before: func(svc services.CAService) (string, string, string, error) {
				// Create initial profile
				originalProfile, err := svc.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Name:     "OriginalProfile",
						Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour * 2)},
					},
				})
				if err != nil {
					return "", "", "", err
				}

				// Create CA
				ca, err := svc.CreateCA(context.Background(), services.CreateCAInput{
					ID:           "test-ca-with-certs",
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "TestCA"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour * 24)},
					ProfileID:    originalProfile.ID,
				})
				if err != nil {
					return "", "", "", err
				}

				// Create new profile
				newProfile, err := svc.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Name:     "NewProfile",
						Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour * 4)},
					},
				})
				if err != nil {
					return "", "", "", err
				}

				// Update CA profile
				_, err = svc.UpdateCAProfile(context.Background(), services.UpdateCAProfileInput{
					CAID:      ca.ID,
					ProfileID: newProfile.ID,
				})
				if err != nil {
					return "", "", "", err
				}

				return ca.ID, originalProfile.ID, newProfile.ID, nil
			},
			run: func(caSDK services.CAService, caID, originalProfileID, newProfileID string) (*models.Certificate, error) {
				// Generate key and CSR for certificate signing
				key, err := chelpers.GenerateRSAKey(2048)
				if err != nil {
					return nil, err
				}

				csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "test-cert"}, key)
				if err != nil {
					return nil, err
				}

				// Sign certificate using the CA with updated profile
				return caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:              caID,
					CertRequest:       (*models.X509CertificateRequest)(csr),
					IssuanceProfileID: newProfileID,
				})
			},
			resultCheck: func(cert *models.Certificate, caID, originalProfileID, newProfileID string, err error) error {
				if err != nil {
					return fmt.Errorf("should've signed certificate without error, but got error: %s", err)
				}

				if cert == nil {
					return fmt.Errorf("certificate should not be nil")
				}

				// Verify certificate was signed with new profile's validity period
				now := time.Now()
				expectedExpiry := now.Add(time.Hour * 4) // New profile validity
				actualExpiry := cert.ValidTo

				// Allow some tolerance for time differences (±1 minute)
				timeDiff := actualExpiry.Sub(expectedExpiry)
				if timeDiff > time.Minute || timeDiff < -time.Minute {
					return fmt.Errorf("certificate expiry doesn't match new profile validity. Expected around %v, got %v", expectedExpiry, actualExpiry)
				}

				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			err = serverTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' func in test case: %s", err)
			}

			caID, originalProfileID, newProfileID, err := tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			cert, err := tc.run(caTest.HttpCASDK, caID, originalProfileID, newProfileID)

			err = tc.resultCheck(cert, caID, originalProfileID, newProfileID, err)
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}
