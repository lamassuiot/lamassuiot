package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"

	"github.com/pressly/goose/v3"
	"github.com/sirupsen/logrus"
)

//go:embed migrations/*.sql
var embedMigrations embed.FS

// RunMigrations runs all pending goose migrations against the authz database.
// Must be called before any store is created. Idempotent — safe on every startup.
func RunMigrations(db *sql.DB, logger *logrus.Entry) error {
	sub, err := fs.Sub(embedMigrations, "migrations")
	if err != nil {
		return fmt.Errorf("prepare embedded migrations: %w", err)
	}

	provider, err := goose.NewProvider(goose.DialectPostgres, db, sub)
	if err != nil {
		return fmt.Errorf("create goose provider: %w", err)
	}

	results, err := provider.Up(context.Background())
	for _, r := range results {
		if r.Error != nil {
			logger.WithError(r.Error).Errorf("migration failed: %s", r.Source.Path)
		} else {
			logger.Infof("migration applied: %s (%.2fs)", r.Source.Path, r.Duration.Seconds())
		}
	}
	return err
}
