package postgrestest

import (
	"context"
	"fmt"
	authzengine "github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/engine"
	authzmodels "github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/models"
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
	"gorm.io/gorm"
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

// Reading from a derived view must retain the physical table's row authorization. The policies are
// turned into SQL by the real authz engine, so the test covers the SQL shape that reaches the plugin.
func TestCertificateViewPreservesAuthorization(t *testing.T) {
	suite, kms, certs := newKMSAndCertStores(t)
	db := suite.DB[postgres.CA_SCHEMA]
	require.NoError(t, db.Use(authzgorm.NewAuthzGormPlugin()))
	cas, err := postgres.NewCAPostgresRepository(helpers.SetupLogger(config.Info, "Test", "authz view"), db)
	require.NoError(t, err)
	insertTestKey(t, kms, "engine", "private")

	// The allowed certificate is the self-signed certificate of CA "ca-allowed"; the forbidden one
	// differs in serial number, subject and issuer.
	allowed := newTestCertificate(t, 401, "engine", "private")
	allowed.Subject.CommonName = "ca.certificates.owner" // a value that looks like a column qualifier
	allowed.IssuerCAMetadata = models.IssuerCAMetadata{ID: "ca-allowed", SN: allowed.SerialNumber}
	forbidden := newTestCertificate(t, 402, "engine", "private")
	for _, cert := range []*models.Certificate{allowed, forbidden} {
		_, err := certs.Insert(context.Background(), cert)
		require.NoError(t, err)
	}
	_, err = cas.Insert(context.Background(), &models.CACertificate{ID: "ca-allowed", CertificateSerialNumber: allowed.SerialNumber,
		Certificate: *allowed, Metadata: map[string]any{}, CreationTS: time.Now()})
	require.NoError(t, err)

	certificateRule := func(r authzmodels.Rule) *authzmodels.Rule {
		r.Namespace, r.SchemaName, r.EntityType, r.Actions = "pki", "ca", "certificate", []string{"read"}
		return &r
	}
	eng := newPKIAuthzEngine(t, db)
	for _, tc := range []struct {
		name  string
		rules []*authzmodels.Rule
		want  int
	}{
		{"restricted", []*authzmodels.Rule{certificateRule(authzmodels.Rule{DirectGrants: []string{allowed.SerialNumber}})}, 1},
		{"deny all", nil, 0},
		{"literal qualifier", []*authzmodels.Rule{certificateRule(authzmodels.Rule{ColumnFilters: []authzmodels.ColumnFilter{
			{Column: "subject_common_name", Type: "string", Operator: "eq", Value: "ca.certificates.owner"}}})}, 1},
		{"join through the issuing CA", []*authzmodels.Rule{{Namespace: "pki", SchemaName: "ca", EntityType: "ca_certificate",
			Actions: []string{"read"}, DirectGrants: []string{"ca-allowed"},
			Relations: []authzmodels.RelationRule{{ToSchemaName: "ca", ToEntityType: "certificate", Via: "issuer_meta_id", Actions: []string{"read"}}}}}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policies := authzengine.NewPolicyRegistry()
			if tc.rules != nil {
				require.NoError(t, policies.AddPolicy(&authzmodels.Policy{ID: "p", Name: "p", Rules: tc.rules}))
			}
			filter, err := eng.GetListFilter(context.Background(), policies, "pki", "ca", "certificate")
			require.NoError(t, err)
			require.Contains(t, filter, "FROM ca.certificates_view certificates", "the engine must read the entity through its view")

			ctx := context.WithValue(context.Background(), authzsdk.AuthzQueryKey, filter)
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
	suite, kms, certs := newKMSAndCertStores(t)
	logger := helpers.SetupLogger(config.Info, "Test", "CA view")
	cas, err := postgres.NewCAPostgresRepository(logger, suite.DB["ca"])
	require.NoError(t, err)
	insertTestKey(t, kms, "engine", "private")
	cert := newTestCertificate(t, 501, "engine", "private")
	_, err = certs.Insert(context.Background(), cert)
	require.NoError(t, err)
	_, err = cas.Insert(context.Background(), &models.CACertificate{ID: "ca-view", CertificateSerialNumber: cert.SerialNumber, Certificate: *cert, Metadata: map[string]any{}, CreationTS: time.Now()})
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

// F10: write responses must include the same derived fields as subsequent reads.
func TestCertificateWriteResponsesMatchView(t *testing.T) {
	_, kms, certs := newKMSAndCertStores(t)
	ctx := context.Background()
	insertTestKey(t, kms, "engine", "private")
	_, err := kms.Insert(ctx, &models.Key{KeyID: "public", EngineID: "engine", PublicKey: "public", HasPrivateKey: false})
	require.NoError(t, err)
	for i, tc := range []struct {
		name, engine, key string
		want              bool
	}{
		{"private key", "engine", "private", true},
		{"public key", "engine", "public", false},
		{"no key", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := newTestCertificate(t, 601+i, tc.engine, tc.key)
			cert.HasPrivateKey = !tc.want // Ignore the caller's value for this read-only field.
			inserted, err := certs.Insert(ctx, cert)
			require.NoError(t, err)
			assert.Equal(t, tc.want, inserted.HasPrivateKey)
			assert.Equal(t, readCertificate(t, certs, cert.SerialNumber), inserted)
			assert.Same(t, cert, inserted)

			cert.Status = models.StatusRevoked
			cert.HasPrivateKey = !tc.want
			updated, err := certs.Update(ctx, cert)
			require.NoError(t, err)
			assert.Equal(t, tc.want, updated.HasPrivateKey)
			assert.Equal(t, readCertificate(t, certs, cert.SerialNumber), updated)
			assert.Equal(t, models.StatusRevoked, updated.Status)
			assert.Same(t, cert, updated)
		})
	}
}

func TestCAWriteResponsesMatchView(t *testing.T) {
	suite, kms, certs := newKMSAndCertStores(t)
	ctx := context.Background()
	cas, err := postgres.NewCAPostgresRepository(helpers.SetupLogger(config.Info, "Test", "CA writes"), suite.DB["ca"])
	require.NoError(t, err)
	insertTestKey(t, kms, "engine", "private")
	for i, tc := range []struct {
		name, engine, key string
		want              bool
	}{
		{"private key", "engine", "private", true},
		{"no key", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := newTestCertificate(t, 701+i, tc.engine, tc.key)
			cert.HasPrivateKey = !tc.want
			_, err := certs.Insert(ctx, cert)
			require.NoError(t, err)
			ca := &models.CACertificate{ID: tc.name, CertificateSerialNumber: cert.SerialNumber, Certificate: *cert, Metadata: map[string]any{"source": "F10"}, CreationTS: time.Now()}
			check := func(got *models.CACertificate) {
				t.Helper()
				found, read, err := cas.SelectExistsByID(ctx, ca.ID)
				require.NoError(t, err)
				require.True(t, found)
				assert.Equal(t, tc.want, got.Certificate.HasPrivateKey)
				assert.Equal(t, read, got)
				assert.Same(t, ca, got)
			}
			inserted, err := cas.Insert(ctx, ca)
			require.NoError(t, err)
			check(inserted)
			ca.Certificate.HasPrivateKey = !tc.want
			ca.Certificate.Status = models.StatusRevoked
			_, err = certs.Update(ctx, &ca.Certificate)
			require.NoError(t, err)
			updated, err := cas.Update(ctx, ca)
			require.NoError(t, err)
			check(updated)
			assert.Equal(t, models.StatusRevoked, updated.Certificate.Status)
		})
	}
}

// Rehydration must retain the caller's read policy, even when the write succeeded.
func TestWriteResponsesRespectReadAuthorization(t *testing.T) {
	suite, kms, certs := newKMSAndCertStores(t)
	ctx := context.Background()
	require.NoError(t, suite.DB["ca"].Use(authzgorm.NewAuthzGormPlugin()))
	insertTestKey(t, kms, "engine", "private")
	cas, err := postgres.NewCAPostgresRepository(helpers.SetupLogger(config.Info, "Test", "CA writes"), suite.DB["ca"])
	require.NoError(t, err)
	t.Run("certificate", func(t *testing.T) {
		denied := context.WithValue(ctx, authzsdk.AuthzQueryKey, "SELECT * FROM ca.certificates WHERE 1 = 0")
		cert := newTestCertificate(t, 801, "engine", "private")
		got, err := certs.Insert(denied, cert)
		require.ErrorIs(t, err, gorm.ErrRecordNotFound)
		require.Nil(t, got)
		cert = readCertificate(t, certs, cert.SerialNumber)
		cert.Status = models.StatusRevoked
		got, err = certs.Update(denied, cert)
		require.ErrorIs(t, err, gorm.ErrRecordNotFound)
		require.Nil(t, got)
	})
	t.Run("CA", func(t *testing.T) {
		denied := context.WithValue(ctx, authzsdk.AuthzQueryKey, "SELECT * FROM ca.ca_certificates WHERE 1 = 0")
		cert := newTestCertificate(t, 802, "engine", "private")
		_, err := certs.Insert(ctx, cert)
		require.NoError(t, err)
		ca := &models.CACertificate{ID: "denied-ca", CertificateSerialNumber: cert.SerialNumber, Certificate: *cert, CreationTS: time.Now()}
		got, err := cas.Insert(denied, ca)
		require.ErrorIs(t, err, gorm.ErrRecordNotFound)
		require.Nil(t, got)
		found, ca, err := cas.SelectExistsByID(ctx, ca.ID)
		require.NoError(t, err)
		require.True(t, found)
		ca.Certificate.Status = models.StatusRevoked
		got, err = cas.Update(denied, ca)
		require.ErrorIs(t, err, gorm.ErrRecordNotFound)
		require.Nil(t, got)
	})
}

// A CA repository owns only CA rows, not the certificates they reference.
func TestCAWritesDoNotWriteCertificates(t *testing.T) {
	suite, kms, certs := newKMSAndCertStores(t)
	ctx := context.Background()
	cas, err := postgres.NewCAPostgresRepository(helpers.SetupLogger(config.Info, "Test", "CA ownership"), suite.DB["ca"])
	require.NoError(t, err)
	insertTestKey(t, kms, "engine", "private")
	t.Run("missing certificate is rejected instead of inserted", func(t *testing.T) {
		cert := newTestCertificate(t, 901, "engine", "private")
		_, err := cas.Insert(ctx, &models.CACertificate{ID: "missing", CertificateSerialNumber: cert.SerialNumber, Certificate: *cert})
		require.ErrorIs(t, err, gorm.ErrForeignKeyViolated)
		found, _, err := certs.SelectExistsBySerialNumber(ctx, cert.SerialNumber)
		require.NoError(t, err)
		assert.False(t, found)
	})
	t.Run("stale associations do not overwrite certificates", func(t *testing.T) {
		cert, err := certs.Insert(ctx, newTestCertificate(t, 902, "engine", "private"))
		require.NoError(t, err)
		stale := *cert
		stale.Status = models.StatusRevoked
		ca, err := cas.Insert(ctx, &models.CACertificate{ID: "reference", CertificateSerialNumber: cert.SerialNumber, Certificate: stale})
		require.NoError(t, err)
		assert.Equal(t, cert, &ca.Certificate)
		ca.Certificate.Status = models.StatusRevoked
		ca.Metadata = map[string]any{"updated": true}
		ca, err = cas.Update(ctx, ca)
		require.NoError(t, err)
		assert.Equal(t, cert, &ca.Certificate)
		assert.Equal(t, cert, readCertificate(t, certs, cert.SerialNumber))
		assert.Equal(t, true, ca.Metadata["updated"])
	})
}
