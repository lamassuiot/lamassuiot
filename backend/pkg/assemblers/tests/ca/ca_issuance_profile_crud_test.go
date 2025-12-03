package ca

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers/tests"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func TestCAIssuanceProfiles(t *testing.T) {
	serverTest, err := tests.TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	assert.NoError(t, err, "could not create CA test server")

	caSvc := serverTest.CA.HttpCASDK

	ctx := context.Background()

	// Create IssuanceProfile
	profile := &models.IssuanceProfile{
		Name:        "TestProfile",
		Description: "Test profile description",
		Validity: models.Validity{
			Type:     "Duration",
			Duration: models.TimeDuration(365 * 24 * 60 * 60 * 1e9), // 1 year in nanoseconds
		},
		SignAsCA: false,
	}
	createInput := services.CreateIssuanceProfileInput{Profile: *profile}
	created, err := caSvc.CreateIssuanceProfile(ctx, createInput)
	assert.NoError(t, err, "failed to create issuance profile")
	assert.Equal(t, profile.Name, created.Name)
	assert.Equal(t, profile.Description, created.Description)
	assert.Equal(t, profile.Validity.Type, created.Validity.Type)
	assert.Equal(t, profile.Validity.Duration, created.Validity.Duration)
	assert.Equal(t, profile.SignAsCA, created.SignAsCA)

	// Get IssuanceProfile by ID
	getInput := services.GetIssuanceProfileByIDInput{ProfileID: created.ID}
	fetched, err := caSvc.GetIssuanceProfileByID(ctx, getInput)
	assert.NoError(t, err, "failed to get issuance profile by ID")
	assert.Equal(t, created.ID, fetched.ID)
	assert.Equal(t, created.Name, fetched.Name)
	assert.Equal(t, created.Description, fetched.Description)
	assert.Equal(t, created.Validity.Type, fetched.Validity.Type)
	assert.Equal(t, created.Validity.Duration, fetched.Validity.Duration)
	assert.Equal(t, created.SignAsCA, fetched.SignAsCA)

	// Update IssuanceProfile
	created.Description = "Updated description"
	updateInput := services.UpdateIssuanceProfileInput{Profile: *created}
	updated, err := caSvc.UpdateIssuanceProfile(ctx, updateInput)
	assert.NoError(t, err, "failed to update issuance profile")
	assert.Equal(t, "Updated description", updated.Description)
	assert.Equal(t, created.ID, updated.ID)
	assert.Equal(t, created.Name, updated.Name)
	assert.Equal(t, created.Validity.Type, updated.Validity.Type)
	assert.Equal(t, created.Validity.Duration, updated.Validity.Duration)
	assert.Equal(t, created.SignAsCA, updated.SignAsCA)

	// List IssuanceProfiles
	var profiles []models.IssuanceProfile
	listInput := services.GetIssuanceProfilesInput{
		ExhaustiveRun: false,
		ApplyFunc: func(item models.IssuanceProfile) {
			profiles = append(profiles, item)
		},
	}
	bookmark, err := caSvc.GetIssuanceProfiles(ctx, listInput)
	assert.NoError(t, err, "failed to list issuance profiles")

	assert.Empty(t, bookmark, "expected empty bookmark after listing all profiles")

	assert.Len(t, profiles, 1, "expected exactly one profile in the list")

	p := profiles[0]
	assert.Equal(t, created.ID, p.ID)
	assert.Equal(t, created.Name, p.Name)
	assert.Equal(t, created.Description, p.Description)
	assert.Equal(t, created.Validity.Type, p.Validity.Type)
	assert.Equal(t, created.Validity.Duration, p.Validity.Duration)
	assert.Equal(t, created.SignAsCA, p.SignAsCA)

	// Delete IssuanceProfile
	deleteInput := services.DeleteIssuanceProfileInput{ProfileID: created.ID}
	err = caSvc.DeleteIssuanceProfile(ctx, deleteInput)
	assert.NoError(t, err, "failed to delete issuance profile")

	// Confirm deletion
	_, err = caSvc.GetIssuanceProfileByID(ctx, getInput)
	assert.Error(t, err, "expected error when fetching deleted profile, got nil")

}

func TestFilterCAsByProfileID(t *testing.T) {
	serverTest, err := tests.TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	assert.NoError(t, err, "could not create CA test server")

	caSvc := serverTest.CA.HttpCASDK
	ctx := context.Background()

	// Create first IssuanceProfile
	profile1 := &models.IssuanceProfile{
		Name:        "Profile1",
		Description: "First test profile",
		Validity: models.Validity{
			Type:     "Duration",
			Duration: models.TimeDuration(365 * 24 * 60 * 60 * 1e9), // 1 year in nanoseconds
		},
		SignAsCA: false,
	}
	createProfile1Input := services.CreateIssuanceProfileInput{Profile: *profile1}
	createdProfile1, err := caSvc.CreateIssuanceProfile(ctx, createProfile1Input)
	assert.NoError(t, err, "failed to create first issuance profile")

	// Create second IssuanceProfile
	profile2 := &models.IssuanceProfile{
		Name:        "Profile2",
		Description: "Second test profile",
		Validity: models.Validity{
			Type:     "Duration",
			Duration: models.TimeDuration(730 * 24 * 60 * 60 * 1e9), // 2 years in nanoseconds
		},
		SignAsCA: false,
	}
	createProfile2Input := services.CreateIssuanceProfileInput{Profile: *profile2}
	createdProfile2, err := caSvc.CreateIssuanceProfile(ctx, createProfile2Input)
	assert.NoError(t, err, "failed to create second issuance profile")

	// Create CAs with different profiles
	caDuration := models.TimeDuration(24 * 60 * 60 * 1e9) // 1 day in nanoseconds

	// Create CA with profile1
	ca1, err := caSvc.CreateCA(ctx, services.CreateCAInput{
		ID:           "ca-with-profile1",
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:      models.Subject{CommonName: "CA with Profile 1"},
		CAExpiration: models.Validity{Type: "Duration", Duration: caDuration},
		ProfileID:    createdProfile1.ID,
	})
	assert.NoError(t, err, "failed to create CA with profile1")
	assert.Equal(t, createdProfile1.ID, ca1.ProfileID, "CA should have profile1 ID")

	// Create another CA with profile1
	ca2, err := caSvc.CreateCA(ctx, services.CreateCAInput{
		ID:           "ca-with-profile1-2",
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:      models.Subject{CommonName: "Second CA with Profile 1"},
		CAExpiration: models.Validity{Type: "Duration", Duration: caDuration},
		ProfileID:    createdProfile1.ID,
	})
	assert.NoError(t, err, "failed to create second CA with profile1")
	assert.Equal(t, createdProfile1.ID, ca2.ProfileID, "Second CA should have profile1 ID")

	// Create CA with profile2
	ca3, err := caSvc.CreateCA(ctx, services.CreateCAInput{
		ID:           "ca-with-profile2",
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:      models.Subject{CommonName: "CA with Profile 2"},
		CAExpiration: models.Validity{Type: "Duration", Duration: caDuration},
		ProfileID:    createdProfile2.ID,
	})
	assert.NoError(t, err, "failed to create CA with profile2")
	assert.Equal(t, createdProfile2.ID, ca3.ProfileID, "CA should have profile2 ID")

	// Test filtering CAs by profile1 ID
	var casWithProfile1 []models.CACertificate
	queryParamsProfile1 := &resources.QueryParameters{
		Filters: []resources.FilterOption{
			{
				Field:           "profile_id",
				FilterOperation: resources.StringEqual,
				Value:           createdProfile1.ID,
			},
		},
	}

	getCAsInputProfile1 := services.GetCAsInput{
		QueryParameters: queryParamsProfile1,
		ExhaustiveRun:   true,
		ApplyFunc: func(ca models.CACertificate) {
			casWithProfile1 = append(casWithProfile1, ca)
		},
	}

	_, err = caSvc.GetCAs(ctx, getCAsInputProfile1)
	assert.NoError(t, err, "failed to get CAs filtered by profile1 ID")

	// Verify that we get exactly 2 CAs with profile1
	assert.Len(t, casWithProfile1, 2, "should get exactly 2 CAs with profile1")

	// Verify that all returned CAs have profile1 ID
	for _, ca := range casWithProfile1 {
		assert.Equal(t, createdProfile1.ID, ca.ProfileID, "all returned CAs should have profile1 ID")
	}

	// Verify specific CAs are returned
	caIDs := make([]string, len(casWithProfile1))
	for i, ca := range casWithProfile1 {
		caIDs[i] = ca.ID
	}
	assert.Contains(t, caIDs, ca1.ID, "should contain first CA with profile1")
	assert.Contains(t, caIDs, ca2.ID, "should contain second CA with profile1")

	// Test filtering CAs by profile2 ID
	var casWithProfile2 []models.CACertificate
	queryParamsProfile2 := &resources.QueryParameters{
		Filters: []resources.FilterOption{
			{
				Field:           "profile_id",
				FilterOperation: resources.StringEqual,
				Value:           createdProfile2.ID,
			},
		},
	}

	getCAsInputProfile2 := services.GetCAsInput{
		QueryParameters: queryParamsProfile2,
		ExhaustiveRun:   true,
		ApplyFunc: func(ca models.CACertificate) {
			casWithProfile2 = append(casWithProfile2, ca)
		},
	}

	_, err = caSvc.GetCAs(ctx, getCAsInputProfile2)
	assert.NoError(t, err, "failed to get CAs filtered by profile2 ID")

	// Verify that we get exactly 1 CA with profile2
	assert.Len(t, casWithProfile2, 1, "should get exactly 1 CA with profile2")
	assert.Equal(t, createdProfile2.ID, casWithProfile2[0].ProfileID, "returned CA should have profile2 ID")
	assert.Equal(t, ca3.ID, casWithProfile2[0].ID, "should return the correct CA with profile2")

	// Test filtering with non-existent profile ID
	var casWithNonExistentProfile []models.CACertificate
	queryParamsNonExistent := &resources.QueryParameters{
		Filters: []resources.FilterOption{
			{
				Field:           "profile_id",
				FilterOperation: resources.StringEqual,
				Value:           "non-existent-profile-id",
			},
		},
	}

	getCAsInputNonExistent := services.GetCAsInput{
		QueryParameters: queryParamsNonExistent,
		ExhaustiveRun:   true,
		ApplyFunc: func(ca models.CACertificate) {
			casWithNonExistentProfile = append(casWithNonExistentProfile, ca)
		},
	}

	_, err = caSvc.GetCAs(ctx, getCAsInputNonExistent)
	assert.NoError(t, err, "should not error when filtering by non-existent profile ID")
	assert.Len(t, casWithNonExistentProfile, 0, "should get no CAs with non-existent profile ID")
}
