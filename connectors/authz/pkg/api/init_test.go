package api

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	authzconfig "github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/store"
)

// The init command seeds the same preload policies as serve, so it must reject the same ones:
// a relation via the schemas do not declare grants nothing and must not be stored.
func TestInitPreloadRejectsUndeclaredVia(t *testing.T) {
	dir := t.TempDir()
	policy := `{
		"id": "bad-via", "name": "Bad via",
		"rules": [{
			"namespace": "pki", "schema_name": "ca", "entity_type": "issuance_profile", "actions": ["read"],
			"relations": [{"to": {"schema_name": "ca", "entity_type": "ca_certificate"}, "via": "parent", "actions": ["read"]}]
		}]
	}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bad-via.json"), []byte(policy), 0o600))

	conf := authzconfig.AuthzConfig{Schemas: map[string]string{"pki": "../../pki.json"}}
	policyStore := store.NewInMemoryPolicyStore()
	pm, err := newInitPolicyManager(conf, policyStore)
	require.NoError(t, err)

	require.NoError(t, preloadPolicies(context.Background(), pm, dir, logrus.NewEntry(logrus.New())))

	_, err = policyStore.Get(context.Background(), "lamassu.bad-via")
	assert.Error(t, err, "init must not store a preload policy whose via the schemas do not declare")
}

func TestInitPolicyManagerFailsOnUnreadableSchema(t *testing.T) {
	conf := authzconfig.AuthzConfig{Schemas: map[string]string{"pki": filepath.Join(t.TempDir(), "missing.json")}}
	_, err := newInitPolicyManager(conf, store.NewInMemoryPolicyStore())
	assert.Error(t, err)
}
