package pkg

import (
	"encoding/json"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The connector writes the RA back as it was when the event happened, possibly after an admin took policies away.
func TestSettingsForWriteBackLeavesTheAuthzPrincipalToTheDMSManager(t *testing.T) {
	settings := models.DMSSettings{
		IssuanceProfileID:      "profile",
		AuthzPrincipalSettings: &models.AuthzPrincipalSettings{Enabled: true, PolicyIDs: []string{"policy-a"}},
	}

	sent := settingsForWriteBack(settings)

	assert.Nil(t, sent.AuthzPrincipalSettings)
	assert.Equal(t, "profile", sent.IssuanceProfileID, "everything else is written back as before")
	assert.NotNil(t, settings.AuthzPrincipalSettings, "the event snapshot is not modified")
	raw, err := json.Marshal(sent)
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"authz_principal_settings":null`, "what the DMS Manager reads as not provided")
}
