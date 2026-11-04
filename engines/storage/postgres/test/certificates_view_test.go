package postgrestest

import (
	"context"
	"fmt"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func readCertificate(t *testing.T, store storage.CertificatesRepo, serial string) *models.Certificate {
	t.Helper()
	found, cert, err := store.SelectExistsBySerialNumber(context.Background(), serial)
	require.NoError(t, err)
	require.True(t, found, "certificate %s not found", serial)
	return cert
}

func TestCertificateViewSelect(t *testing.T) {
	suite, kmsStore, certStore := newKMSAndCertStores(t)

	t.Run("ReferencedKeyWithPrivateKey", func(t *testing.T) {
		insertTestKey(t, kmsStore, "engine-a", "key-priv")
		cert := newTestCertificate(t, 101, "engine-a", "key-priv")
		_, err := certStore.Insert(context.Background(), cert)
		require.NoError(t, err)

		assert.True(t, readCertificate(t, certStore, cert.SerialNumber).HasPrivateKey)
	})

	t.Run("ReferencedKeyWithoutPrivateKey", func(t *testing.T) {
		_, err := kmsStore.Insert(context.Background(), &models.Key{
			KeyID: "key-pub", EngineID: "engine-a", Name: "key-pub", Algorithm: "ECDSA", Size: 256,
			PublicKey: "pub-key-pub", HasPrivateKey: false, Aliases: []string{}, Tags: []string{}, Metadata: map[string]any{},
		})
		require.NoError(t, err)
		cert := newTestCertificate(t, 102, "engine-a", "key-pub")
		_, err = certStore.Insert(context.Background(), cert)
		require.NoError(t, err)

		assert.False(t, readCertificate(t, certStore, cert.SerialNumber).HasPrivateKey)
	})

	t.Run("ReferenceToMissingKey", func(t *testing.T) {
		cert := newTestCertificate(t, 103, "engine-a", "key-gone")
		_, err := certStore.Insert(context.Background(), cert)
		require.Error(t, err, "the FK must reject an unknown key reference")
		require.NoError(t, suite.DB["ca"].Exec("ALTER TABLE ca.certificates DROP CONSTRAINT certificates_key_fk").Error)

		_, err = certStore.Insert(context.Background(), cert)
		require.NoError(t, err)
		assert.False(t, readCertificate(t, certStore, cert.SerialNumber).HasPrivateKey)
	})

	t.Run("WithoutKeyReference", func(t *testing.T) {
		cert := newTestCertificate(t, 104, "", "")
		_, err := certStore.Insert(context.Background(), cert)
		require.NoError(t, err)

		assert.False(t, readCertificate(t, certStore, cert.SerialNumber).HasPrivateKey)
	})
}

func TestCertificateViewWritesHitTheTable(t *testing.T) {
	suite, kmsStore, certStore := newKMSAndCertStores(t)

	insertTestKey(t, kmsStore, "engine-a", "key-priv")
	cert := newTestCertificate(t, 201, "engine-a", "key-priv")
	_, err := certStore.Insert(context.Background(), cert)
	require.NoError(t, err)

	var tableColumns []string
	require.NoError(t, suite.DB["ca"].Raw(
		"SELECT column_name FROM information_schema.columns WHERE table_schema = 'ca' AND table_name = 'certificates'",
	).Pluck("column_name", &tableColumns).Error)
	assert.NotContains(t, tableColumns, "has_private_key", "the field is derived, not stored in the table")

	cert.Status = models.StatusRevoked
	_, err = certStore.Update(context.Background(), cert)
	require.NoError(t, err)
	assert.Equal(t, models.StatusRevoked, readCertificate(t, certStore, cert.SerialNumber).Status, "the view must reflect table updates")
}

func TestCertificateViewFilterAndCount(t *testing.T) {
	_, kmsStore, certStore := newKMSAndCertStores(t)

	insertTestKey(t, kmsStore, "engine-a", "key-priv")
	_, err := kmsStore.Insert(context.Background(), &models.Key{
		KeyID: "key-pub", EngineID: "engine-a", Name: "key-pub", Algorithm: "ECDSA", Size: 256,
		PublicKey: "pub-key-pub", HasPrivateKey: false, Aliases: []string{}, Tags: []string{}, Metadata: map[string]any{},
	})
	require.NoError(t, err)

	privCert := newTestCertificate(t, 301, "engine-a", "key-priv")
	_, err = certStore.Insert(context.Background(), privCert)
	require.NoError(t, err)
	pubCert := newTestCertificate(t, 302, "engine-a", "key-pub")
	_, err = certStore.Insert(context.Background(), pubCert)
	require.NoError(t, err)

	for _, want := range []bool{true, false} {
		filters := []resources.FilterOption{
			{Field: "has_private_key", FilterOperation: resources.EnumEqual, Value: fmt.Sprintf("%v", want)},
		}

		seen := map[string]bool{}
		_, err := certStore.SelectAll(context.Background(), storage.StorageListRequest[models.Certificate]{
			QueryParams:   &resources.QueryParameters{Filters: filters},
			ExhaustiveRun: true,
			ApplyFunc: func(c models.Certificate) {
				seen[c.SerialNumber] = c.HasPrivateKey
			},
		})
		require.NoError(t, err)
		require.Len(t, seen, 1)
		for serial, hasPriv := range seen {
			assert.Equal(t, want, hasPriv)
			if want {
				assert.Equal(t, privCert.SerialNumber, serial)
			} else {
				assert.Equal(t, pubCert.SerialNumber, serial)
			}
		}

		count, err := certStore.CountWithFilters(context.Background(), &resources.QueryParameters{Filters: filters})
		require.NoError(t, err)
		assert.Equal(t, 1, count)
	}
}
