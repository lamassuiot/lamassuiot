package sqlite

import (
	"context"
	"io"
	"path/filepath"
	"sync"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"
	"github.com/sirupsen/logrus"
)

// El repositorio de eventos de PostgreSQL también sirve a SQLite: el upsert atómico de
// InsertUpdateEvent (006 T10) debe funcionar con su dialecto (MAX en lugar de GREATEST).
func TestEventsInsertUpdateUpsertsOnSQLite(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	lEntry := logrus.NewEntry(logger)

	db, err := CreateSQLiteDBConnection(lEntry, filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatalf("failed to create sqlite connection: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("failed to get sql DB: %v", err)
	}
	t.Cleanup(func() {
		_ = sqlDB.Close()
	})
	if err := initializeSchema(db); err != nil {
		t.Fatalf("failed to initialize schema: %v", err)
	}

	repo, err := postgres.NewEventsPostgresRepository(lEntry, db)
	if err != nil {
		t.Fatalf("failed to create events repository: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	record := func(tenant string, seen time.Time) error {
		ev := cloudevents.NewEvent()
		ev.SetID(seen.String())
		ev.SetSource("test")
		ev.SetType("ca.create")
		_, err := repo.InsertUpdateEvent(context.Background(), &models.AlertLatestEvent{
			TenantID:  tenant,
			EventType: "ca.create",
			Event:     ev,
			LastSeen:  seen,
		})
		return err
	}

	const n = 10
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- record("tenant-a", now)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent InsertUpdateEvent failed: %v", err)
		}
	}

	// Un evento más antiguo cuenta, pero no retrasa last_seen.
	if err := record("tenant-a", now.Add(-time.Hour)); err != nil {
		t.Fatalf("InsertUpdateEvent failed: %v", err)
	}
	if err := record("tenant-b", now); err != nil {
		t.Fatalf("InsertUpdateEvent failed: %v", err)
	}

	var rows []models.AlertLatestEvent
	if err := db.Table("events").Order("tenant_id").Find(&rows).Error; err != nil {
		t.Fatalf("failed to read events: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2 (one per tenant)", len(rows))
	}
	if rows[0].TenantID != "tenant-a" || rows[0].TotalSeen != n+1 {
		t.Errorf("tenant-a: got tenant=%s total_seen=%d, want total_seen=%d", rows[0].TenantID, rows[0].TotalSeen, n+1)
	}
	if !rows[0].LastSeen.Equal(now) {
		t.Errorf("tenant-a: last_seen=%s, want %s", rows[0].LastSeen, now)
	}
	if rows[1].TenantID != "tenant-b" || rows[1].TotalSeen != 1 {
		t.Errorf("tenant-b: got tenant=%s total_seen=%d, want total_seen=1", rows[1].TenantID, rows[1].TotalSeen)
	}
}
