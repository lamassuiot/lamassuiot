package services

import (
	"context"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// singleKeyStorage holds one key and records updates; any other call fails the test.
type singleKeyStorage struct {
	storage.KMSKeysRepo
	key     *models.Key
	updates int
}

func (s *singleKeyStorage) SelectExistsByKeyID(_ context.Context, keyID, engineID string) (bool, *models.Key, error) {
	return keyID == s.key.KeyID && engineID == s.key.EngineID, s.key, nil
}

func (s *singleKeyStorage) Update(_ context.Context, key *models.Key) (*models.Key, error) {
	s.updates++
	return key, nil
}

// The bound resources keep a key in use from being deleted, so a binding change must not replace
// bindings it cannot read: that would drop the record of the resources still using the key.
func TestKeyBindingChangesFailOnUnreadableBindings(t *testing.T) {
	for name, change := range map[string]func(services.KMSService, context.Context, services.KeyResourceBindingInput) (*models.Key, error){
		"Bind":   services.KMSService.BindKeyResource,
		"Unbind": services.KMSService.UnbindKeyResource,
	} {
		t.Run(name, func(t *testing.T) {
			store := &singleKeyStorage{key: &models.Key{
				KeyID:    "key-1",
				EngineID: "engine-1",
				Metadata: map[string]any{models.KMSBindResourceKey: "not json"},
			}}
			kms, err := NewKMSService(KMSServiceBuilder{
				Logger:        logrus.NewEntry(logrus.New()),
				CryptoEngines: map[string]*Engine{"engine-1": {Default: true}},
				KMSStorage:    store,
			})
			require.NoError(t, err)

			_, err = change(kms, context.Background(), services.KeyResourceBindingInput{
				Identifier: buildPKCS11ID("engine-1", "key-1", "private"),
				Resource:   models.KMSBindResource{ResourceType: models.KMSBindResourceTypeCertificate, ResourceID: "aa-01"},
			})

			assert.Error(t, err)
			assert.Zero(t, store.updates, "the unreadable bindings must be kept")
			assert.Equal(t, "not json", store.key.Metadata[models.KMSBindResourceKey])
		})
	}
}
