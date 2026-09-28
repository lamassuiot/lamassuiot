package postgrestest

import (
	"fmt"
	"math/big"
	"sort"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	postgresstorage "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// Regresión de la lectura exhaustiva (SelectAll con exhaustiveRun) sobre tablas cuyo modelo
// gorm no tiene una PK simple: events (PK compuesta tenant_id, event_type), va_role y
// kms_keys (modelos sin campo de PK). FindInBatches de gorm fallaba con «primary key
// required» en cuanto había más filas que el tamaño de lote (15 por defecto).
const exhaustiveRows = 40

func setupExhaustiveAppDB(t *testing.T, dbName string, password string) *gorm.DB {
	cfg, suite := BeforeSuite([]string{dbName, postgresstorage.CONTROLPLANE_DB_NAME}, false)
	t.Cleanup(suite.AfterSuite)

	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Exhaustive pagination test")
	require.NoError(t, postgresstorage.MigrateDatabase(logger, cfg, postgresstorage.CONTROLPLANE_DB_NAME))
	require.NoError(t, postgresstorage.MigrateDatabase(logger, cfg, dbName))
	require.NoError(t, suite.DB[postgresstorage.CONTROLPLANE_DB_NAME].Exec("ALTER ROLE lamassu_app PASSWORD '"+password+"'").Error)

	// Como en producción: rol lamassu_app, sujeto a RLS.
	return openTenantAppDB(t, cfg.Hostname, cfg.Port, dbName, password)
}

func expectedIDs(prefix string, n int) []string {
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		ids = append(ids, fmt.Sprintf("%s-%02d", prefix, i))
	}
	sort.Strings(ids)
	return ids
}

func TestEventsGetLatestEventsWithManyEventTypes(t *testing.T) {
	appDB := setupExhaustiveAppDB(t, postgresstorage.ALERTS_DB_NAME, "exhaustive-events-test")
	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Events exhaustive test")
	repo, err := postgresstorage.NewEventsPostgresRepository(logger, appDB)
	require.NoError(t, err)

	record := func(tenant, evType string) {
		ev := cloudevents.NewEvent()
		ev.SetID(evType)
		ev.SetSource("test")
		ev.SetType(evType)
		_, err := repo.InsertUpdateEvent(testTenantContext(tenant), &models.AlertLatestEvent{
			TenantID:  tenant,
			EventType: models.EventType(evType),
			Event:     ev,
			LastSeen:  time.Now(),
		})
		require.NoError(t, err)
	}

	for _, evType := range expectedIDs("ev.a", exhaustiveRows) {
		record("tenant-a", evType)
	}
	// El otro tenant comparte parte de los tipos: no debe aparecer en la lectura de tenant-a.
	for _, evType := range expectedIDs("ev.a", 5) {
		record("tenant-b", evType)
	}
	record("tenant-b", "ev.b-only")

	events, err := repo.GetLatestEvents(testTenantContext("tenant-a"))
	require.NoError(t, err)

	got := []string{}
	for _, ev := range events {
		assert.Equal(t, "tenant-a", ev.TenantID)
		got = append(got, string(ev.EventType))
	}
	sort.Strings(got)
	assert.Equal(t, expectedIDs("ev.a", exhaustiveRows), got)

	events, err = repo.GetLatestEvents(testTenantContext("tenant-b"))
	require.NoError(t, err)
	assert.Len(t, events, 6)
}

func TestVARolesExhaustiveSelectAllWithManyRoles(t *testing.T) {
	appDB := setupExhaustiveAppDB(t, postgresstorage.VA_DB_NAME, "exhaustive-va-test")
	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "VA exhaustive test")
	repo, err := postgresstorage.NewVARepository(logger, appDB)
	require.NoError(t, err)

	insert := func(tenant, ski string) {
		_, err := repo.Insert(testTenantContext(tenant), &models.VARole{
			CASubjectKeyID: ski,
			TenantID:       tenant,
			LatestCRL:      models.LatestCRLMeta{Version: models.BigInt{Int: big.NewInt(0)}},
		})
		require.NoError(t, err)
	}
	for _, ski := range expectedIDs("ski", exhaustiveRows) {
		insert("tenant-a", ski)
	}
	for _, ski := range expectedIDs("ski", 3) {
		insert("tenant-b", ski)
	}

	list := func(t *testing.T, tenant string, qp *resources.QueryParameters) []string {
		got := []string{}
		_, err := repo.GetAll(testTenantContext(tenant), storage.StorageListRequest[models.VARole]{
			ExhaustiveRun: true,
			QueryParams:   qp,
			ApplyFunc: func(role models.VARole) {
				assert.Equal(t, tenant, role.TenantID)
				got = append(got, role.CASubjectKeyID)
			},
		})
		require.NoError(t, err)
		return got
	}

	t.Run("lote por defecto", func(t *testing.T) {
		got := list(t, "tenant-a", nil)
		sort.Strings(got)
		assert.Equal(t, expectedIDs("ski", exhaustiveRows), got)
	})

	t.Run("lote pequeño sin duplicados ni huecos", func(t *testing.T) {
		got := list(t, "tenant-a", &resources.QueryParameters{PageSize: 7})
		sort.Strings(got)
		assert.Equal(t, expectedIDs("ski", exhaustiveRows), got)
	})

	t.Run("orden descendente respetado", func(t *testing.T) {
		got := list(t, "tenant-a", &resources.QueryParameters{
			PageSize: 7,
			Sort:     resources.SortOptions{SortMode: resources.SortModeDesc, SortField: "ca_ski"},
		})
		want := expectedIDs("ski", exhaustiveRows)
		sort.Sort(sort.Reverse(sort.StringSlice(want)))
		assert.Equal(t, want, got)
	})

	t.Run("otro tenant", func(t *testing.T) {
		assert.Len(t, list(t, "tenant-b", &resources.QueryParameters{PageSize: 2}), 3)
	})
}

func TestKMSKeysExhaustiveSelectAllWithManyKeys(t *testing.T) {
	appDB := setupExhaustiveAppDB(t, postgresstorage.KMS_DB_NAME, "exhaustive-kms-test")
	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "KMS exhaustive test")
	repo, err := postgresstorage.NewKMSPostgresRepository(logger, appDB)
	require.NoError(t, err)

	insert := func(tenant, keyID string) {
		_, err := repo.Insert(testTenantContext(tenant), &models.Key{
			KeyID:      tenant + "-" + keyID,
			TenantID:   tenant,
			Name:       tenant + "-" + keyID,
			EngineID:   "filesystem-1",
			Algorithm:  "ECDSA",
			Size:       256,
			CreationTS: time.Now(),
		})
		require.NoError(t, err)
	}
	for _, keyID := range expectedIDs("key", exhaustiveRows) {
		insert("tenant-a", keyID)
	}
	insert("tenant-b", "key-00")

	got := []string{}
	_, err = repo.SelectAll(testTenantContext("tenant-a"), storage.StorageListRequest[models.Key]{
		ExhaustiveRun: true,
		ApplyFunc: func(key models.Key) {
			assert.Equal(t, "tenant-a", key.TenantID)
			got = append(got, key.KeyID)
		},
	})
	require.NoError(t, err)
	assert.Len(t, got, exhaustiveRows)
}
