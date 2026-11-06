package postgrestest

import (
	"context"
	"testing"
	"time"

	authzengine "github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/engine"
	authzmodels "github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/models"
	authzsdk "github.com/lamassuiot/lamassuiot/v4/connectors/authz/sdk"
	authzgorm "github.com/lamassuiot/lamassuiot/v4/connectors/authz/sdk/gorm"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

const pkiAuthzSchema = "../../../../connectors/authz/pki.json"

// hasPrivateKeyFixture has two CAs: one whose key the KMS holds and one whose key it does not.
type hasPrivateKeyFixture struct {
	db                      *gorm.DB
	certs                   storage.CertificatesRepo
	cas                     storage.CACertificatesRepo
	withKey, withoutKey     *models.Certificate
	caWithKey, caWithoutKey string
}

func newHasPrivateKeyFixture(t *testing.T) hasPrivateKeyFixture {
	t.Helper()
	suite, kms, certs := newKMSAndCertStores(t)
	db := suite.DB[postgres.CA_SCHEMA]
	require.NoError(t, db.Use(authzgorm.NewAuthzGormPlugin()))
	cas, err := postgres.NewCAPostgresRepository(helpers.SetupLogger(config.Info, "Test", "authz"), db)
	require.NoError(t, err)

	insertTestKey(t, kms, "engine", "private")
	_, err = kms.Insert(context.Background(), &models.Key{
		KeyID: "public", EngineID: "engine", Name: "public", Algorithm: "ECDSA", Size: 256, PublicKey: "pub-public",
		HasPrivateKey: false, Aliases: []string{}, Tags: []string{}, Metadata: map[string]any{},
	})
	require.NoError(t, err)

	f := hasPrivateKeyFixture{db: db, certs: certs, cas: cas, caWithKey: "ca-with-key", caWithoutKey: "ca-without-key",
		withKey: newTestCertificate(t, 601, "engine", "private"), withoutKey: newTestCertificate(t, 602, "engine", "public")}
	for id, cert := range map[string]*models.Certificate{f.caWithKey: f.withKey, f.caWithoutKey: f.withoutKey} {
		_, err := cas.Insert(context.Background(), &models.CACertificate{ID: id, Certificate: *cert, Metadata: map[string]any{}, CreationTS: time.Now()})
		require.NoError(t, err)
	}
	return f
}

func newPKIAuthzEngine(t *testing.T, db *gorm.DB) *authzengine.Engine {
	t.Helper()
	eng, err := authzengine.NewEngine(map[string]*gorm.DB{"pki": db}, map[string]string{"pki": pkiAuthzSchema})
	require.NoError(t, err)
	return eng
}

func certificatePolicy(t *testing.T, filters []authzmodels.ColumnFilter, relations []authzmodels.RelationRule) *authzengine.PolicyRegistry {
	t.Helper()
	policies := authzengine.NewPolicyRegistry()
	require.NoError(t, policies.AddPolicy(&authzmodels.Policy{ID: "certificates", Name: "certificates", Rules: []*authzmodels.Rule{{
		Namespace: "pki", SchemaName: "ca", EntityType: "certificate", Actions: []string{"read"},
		ColumnFilters: filters, Relations: relations,
	}}}))
	return policies
}

func listCertificates(t *testing.T, f hasPrivateKeyFixture, ctx context.Context) []string {
	t.Helper()
	var serials []string
	_, err := f.certs.SelectAll(ctx, storage.StorageListRequest[models.Certificate]{ExhaustiveRun: true,
		ApplyFunc: func(c models.Certificate) { serials = append(serials, c.SerialNumber) }})
	require.NoError(t, err)
	return serials
}

func listCAs(t *testing.T, f hasPrivateKeyFixture, ctx context.Context, params *resources.QueryParameters) []string {
	t.Helper()
	var ids []string
	_, err := f.cas.SelectAll(ctx, storage.StorageListRequest[models.CACertificate]{ExhaustiveRun: true, QueryParams: params,
		ApplyFunc: func(c models.CACertificate) { ids = append(ids, c.ID) }})
	require.NoError(t, err)
	return ids
}

func TestAuthzPolicyFiltersCertificatesByHasPrivateKey(t *testing.T) {
	f := newHasPrivateKeyFixture(t)
	eng := newPKIAuthzEngine(t, f.db)
	policies := certificatePolicy(t,
		[]authzmodels.ColumnFilter{{Column: "has_private_key", Type: "bool", Operator: "eq", Value: true}},
		[]authzmodels.RelationRule{{ToSchemaName: "ca", ToEntityType: "ca_certificate", To: "ca.ca_certificate", Via: "serial_number", Actions: []string{"read"}}})
	ctx := context.Background()

	t.Run("certificate list", func(t *testing.T) {
		filter, err := eng.GetListFilter(ctx, policies, "pki", "ca", "certificate")
		require.NoError(t, err)
		serials := listCertificates(t, f, context.WithValue(ctx, authzsdk.AuthzQueryKey, filter))
		assert.Equal(t, []string{f.withKey.SerialNumber}, serials)
	})

	t.Run("certificate atomic check", func(t *testing.T) {
		for serial, want := range map[string]bool{f.withKey.SerialNumber: true, f.withoutKey.SerialNumber: false} {
			allowed, err := eng.Authorize(ctx, policies, "pki", "ca", "read", "certificate", map[string]string{"serial_number": serial})
			require.NoError(t, err)
			assert.Equal(t, want, allowed, serial)
		}
	})

	t.Run("cascades to the CA of that certificate", func(t *testing.T) {
		for id, want := range map[string]bool{f.caWithKey: true, f.caWithoutKey: false} {
			allowed, err := eng.Authorize(ctx, policies, "pki", "ca", "read", "ca_certificate", map[string]string{"id": id})
			require.NoError(t, err)
			assert.Equal(t, want, allowed, id)
		}
		filter, err := eng.GetListFilter(ctx, policies, "pki", "ca", "ca_certificate")
		require.NoError(t, err)
		assert.Equal(t, []string{f.caWithKey}, listCAs(t, f, context.WithValue(ctx, authzsdk.AuthzQueryKey, filter), nil))
	})
}

func TestAuthzPolicyWithoutHasPrivateKeyStillWorksOnCertificates(t *testing.T) {
	f := newHasPrivateKeyFixture(t)
	eng := newPKIAuthzEngine(t, f.db)
	policies := authzengine.NewPolicyRegistry()
	require.NoError(t, policies.AddPolicy(&authzmodels.Policy{ID: "direct", Name: "direct", Rules: []*authzmodels.Rule{{
		Namespace: "pki", SchemaName: "ca", EntityType: "certificate", Actions: []string{"read"},
		DirectGrants: []string{f.withoutKey.SerialNumber},
	}}}))
	ctx := context.Background()

	filter, err := eng.GetListFilter(ctx, policies, "pki", "ca", "certificate")
	require.NoError(t, err)
	assert.Equal(t, []string{f.withoutKey.SerialNumber}, listCertificates(t, f, context.WithValue(ctx, authzsdk.AuthzQueryKey, filter)))
	for serial, want := range map[string]bool{f.withKey.SerialNumber: false, f.withoutKey.SerialNumber: true} {
		allowed, err := eng.Authorize(ctx, policies, "pki", "ca", "read", "certificate", map[string]string{"serial_number": serial})
		require.NoError(t, err)
		assert.Equal(t, want, allowed, serial)
	}
}

func TestCAFilterByHasPrivateKey(t *testing.T) {
	f := newHasPrivateKeyFixture(t)
	for want, id := range map[bool]string{true: f.caWithKey, false: f.caWithoutKey} {
		params := &resources.QueryParameters{Filters: []resources.FilterOption{
			{Field: "has_private_key", FilterOperation: resources.EnumEqual, Value: map[bool]string{true: "true", false: "false"}[want]},
		}}
		assert.Equal(t, []string{id}, listCAs(t, f, context.Background(), params), "has_private_key=%v", want)
	}
}
