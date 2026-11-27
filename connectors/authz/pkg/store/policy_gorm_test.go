package store

import (
	"context"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/testutil"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGormPolicyStore_ListWarnsAboutUnreadablePolicies checks that a stored
// policy whose rules cannot be decoded is left out of List and Search, the
// other policies are still returned, and a warning names the skipped policy.
func TestGormPolicyStore_ListWarnsAboutUnreadablePolicies(t *testing.T) {
	container, err := testutil.RunEmpty()
	require.NoError(t, err)
	defer container.Cleanup()

	sqlDB, err := container.DB.DB()
	require.NoError(t, err)

	log := logrus.NewEntry(logrus.New())
	log.Logger.SetLevel(logrus.ErrorLevel)
	require.NoError(t, RunMigrationsForProvider(sqlDB, "", testutil.StorageProvider(), log))

	logger, hook := logtest.NewNullLogger()
	s, err := NewGormPolicyStore(container.DB, WithPolicyStoreLogger(logrus.NewEntry(logger)))
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, s.Create(ctx, &models.Policy{ID: "readable-policy", Name: "Readable", Rules: []*models.Rule{}}))
	// Valid JSON that is not a list of rules, as a damaged or hand-edited row.
	require.NoError(t, container.DB.WithContext(ctx).Create(&models.PolicyRecord{
		ID: "unreadable-policy", Name: "Unreadable", Rules: models.JSONDocument(`{"not":"a rule list"}`),
	}).Error)

	listed, _, err := s.List(ctx, nil)
	require.NoError(t, err)
	searched, err := s.Search(ctx, "policy")
	require.NoError(t, err)
	for name, policies := range map[string][]*models.Policy{"list": listed, "search": searched} {
		require.Len(t, policies, 1, name)
		assert.Equal(t, "readable-policy", policies[0].ID, name)
	}

	var warnings []string
	for _, entry := range hook.AllEntries() {
		if entry.Level == logrus.WarnLevel {
			warnings = append(warnings, entry.Message)
		}
	}
	require.Len(t, warnings, 2, "one warning for List and one for Search")
	for _, warning := range warnings {
		assert.Contains(t, warning, `"unreadable-policy"`)
	}
}
