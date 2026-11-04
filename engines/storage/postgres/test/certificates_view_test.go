package postgrestest

import (
	"context"
	"fmt"
	authzsdk "github.com/lamassuiot/lamassuiot/v4/connectors/authz/sdk"
	authzgorm "github.com/lamassuiot/lamassuiot/v4/connectors/authz/sdk/gorm"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	"testing"
	"time"

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

// Reading from a derived view must retain the physical table's row authorization.
func TestCertificateViewPreservesAuthorization(t *testing.T) {
	suite, kms, certs := newKMSAndCertStores(t)
	require.NoError(t, suite.DB["ca"].Use(authzgorm.NewAuthzGormPlugin()))
	insertTestKey(t, kms, "engine", "private")
	allowed := newTestCertificate(t, 401, "engine", "private")
	forbidden := newTestCertificate(t, 402, "engine", "private")
	for _, cert := range []*models.Certificate{allowed, forbidden} {
		_, err := certs.Insert(context.Background(), cert)
		require.NoError(t, err)
	}
	require.NoError(t, suite.DB["ca"].Exec(`CREATE TABLE certificate_grants (serial_number text, owner text)`).Error)
	require.NoError(t, suite.DB["ca"].Exec(`INSERT INTO certificate_grants VALUES (?, 'ca.certificates.owner')`, allowed.SerialNumber).Error)
	for _, tc := range []struct {
		name, sql string
		want      int
	}{
		{"restricted", "SELECT * FROM ca.certificates WHERE ca.certificates.serial_number = '" + allowed.SerialNumber + "'", 1},
		{"deny all", "SELECT * FROM ca.certificates WHERE 1 = 0", 0},
		{"grant join and literal qualifier", `SELECT * FROM ca.certificates LEFT JOIN ca.certificate_grants AS j0_0 ON ca.certificates.serial_number = j0_0.serial_number WHERE j0_0.owner = 'ca.certificates.owner'`, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), authzsdk.AuthzQueryKey, tc.sql)
			for _, exhaustive := range []bool{false, true} {
				var serials []string
				_, err := certs.SelectAll(ctx, storage.StorageListRequest[models.Certificate]{ExhaustiveRun: exhaustive, ApplyFunc: func(c models.Certificate) { serials = append(serials, c.SerialNumber) }})
				require.NoError(t, err)
				assert.Len(t, serials, tc.want)
				assert.NotContains(t, serials, forbidden.SerialNumber)
			}
			count, err := certs.Count(ctx)
			require.NoError(t, err)
			assert.Equal(t, tc.want, count)
			found, _, err := certs.SelectExistsBySerialNumber(ctx, forbidden.SerialNumber)
			require.NoError(t, err)
			assert.False(t, found)
		})
	}
}

func TestCAReadsCertificatePrivateKeyFromView(t *testing.T) {
	suite, kms, _ := newKMSAndCertStores(t)
	logger := helpers.SetupLogger(config.Info, "Test", "CA view")
	cas, err := postgres.NewCAPostgresRepository(logger, suite.DB["ca"])
	require.NoError(t, err)
	insertTestKey(t, kms, "engine", "private")
	cert := newTestCertificate(t, 501, "engine", "private")
	_, err = cas.Insert(context.Background(), &models.CACertificate{ID: "ca-view", Certificate: *cert, Metadata: map[string]any{}, CreationTS: time.Now()})
	require.NoError(t, err)
	found, ca, err := cas.SelectExistsByID(context.Background(), "ca-view")
	require.NoError(t, err)
	require.True(t, found)
	assert.True(t, ca.Certificate.HasPrivateKey)
	seen := 0
	_, err = cas.SelectAll(context.Background(), storage.StorageListRequest[models.CACertificate]{ApplyFunc: func(c models.CACertificate) {
		seen++
		assert.True(t, c.Certificate.HasPrivateKey)
	}})
	require.NoError(t, err)
	assert.Equal(t, 1, seen)
}
