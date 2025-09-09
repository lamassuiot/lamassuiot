package assemblers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func TestCAIssuanceProfiles(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").Build(t)
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
