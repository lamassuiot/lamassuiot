package postgres

import (
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	postgrestest "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/test"
	"github.com/stretchr/testify/require"
)

func TestCARepositoryTenantScopeWithJoinedQueries(t *testing.T) {
	logger := helpers.SetupLogger(config.Info, "test", "ca-repo-tenant-scope")
	_, suite := postgrestest.BeforeSuite([]string{caDBName}, false)
	defer suite.AfterSuite()

	db := suite.DB[caDBName]
	_, err := NewCAPostgresRepository(logger, db)
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Certificate{}, &models.CACertificate{}))

	repo, err := NewCAPostgresRepository(logger, db)
	require.NoError(t, err)

	ctx := deviceGroupsTenantContext("00000000-0000-0000-0000-00000000000a")
	listRequest := storage.StorageListRequest[models.CACertificate]{}
	queryParams := &resources.QueryParameters{}

	joinedQueries := []struct {
		name string
		run  func() error
	}{
		{
			name: "count with filters",
			run: func() error {
				_, err := repo.CountWithFilters(ctx, queryParams)
				return err
			},
		},
		{
			name: "count by engine",
			run: func() error {
				_, err := repo.CountByEngine(ctx, "engine")
				return err
			},
		},
		{
			name: "count by engine with filters",
			run: func() error {
				_, err := repo.CountByEngineWithFilters(ctx, "engine", queryParams)
				return err
			},
		},
		{
			name: "count by status",
			run: func() error {
				_, err := repo.CountByStatus(ctx, models.StatusActive)
				return err
			},
		},
		{
			name: "select by type",
			run: func() error {
				_, err := repo.SelectByType(ctx, models.CertificateTypeManaged, listRequest)
				return err
			},
		},
		{
			name: "select all",
			run: func() error {
				_, err := repo.SelectAll(ctx, listRequest)
				return err
			},
		},
		{
			name: "select by common name",
			run: func() error {
				_, err := repo.SelectByCommonName(ctx, "common-name", listRequest)
				return err
			},
		},
		{
			name: "select by parent CA",
			run: func() error {
				_, err := repo.SelectByParentCA(ctx, "parent-ca", listRequest)
				return err
			},
		},
		{
			name: "select by subject and subject key ID",
			run: func() error {
				_, err := repo.SelectBySubjectAndSubjectKeyID(ctx, models.Subject{}, "subject-key-id", listRequest)
				return err
			},
		},
		{
			name: "select by issuer and authority key ID",
			run: func() error {
				_, err := repo.SelectByIssuerAndAuthorityKeyID(ctx, models.Subject{}, "authority-key-id", listRequest)
				return err
			},
		},
	}

	for _, query := range joinedQueries {
		t.Run(query.name, func(t *testing.T) {
			require.NoError(t, query.run())
		})
	}
}
