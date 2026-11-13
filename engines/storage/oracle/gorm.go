package oracle

import (
	"database/sql"
	"fmt"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage/serializers"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/oracle/dialect"
	"gorm.io/gorm"
	"gorm.io/plugin/opentelemetry/tracing"
)

var registeredPlugins []gorm.Plugin

// RegisterGORMPlugin adds a plugin to Oracle storage-engine connections.
// Call it during package initialization, before creating storage engines.
func RegisterGORMPlugin(plugin gorm.Plugin) {
	registeredPlugins = append(registeredPlugins, plugin)
}

// openGORM wraps an already verified pool and installs tracing and the
// configured plugins. The caller remains responsible for closing the pool.
func openGORM(pool *sql.DB, plugins ...gorm.Plugin) (*gorm.DB, error) {
	serializers.Register()
	db, err := gorm.Open(dialect.Dialector{Conn: pool}, &gorm.Config{DisableAutomaticPing: true})
	if err != nil {
		return nil, fmt.Errorf("open oracle GORM: %w", err)
	}
	if err := db.Use(tracing.NewPlugin()); err != nil {
		return nil, fmt.Errorf("install oracle tracing: %w", err)
	}
	for _, plugin := range plugins {
		if err := db.Use(plugin); err != nil {
			return nil, fmt.Errorf("install oracle GORM plugin %q: %w", plugin.Name(), err)
		}
	}
	return db, nil
}

// OpenGORM creates an Oracle GORM connection from an already verified pool.
func OpenGORM(pool *sql.DB, plugins ...gorm.Plugin) (*gorm.DB, error) {
	return openGORM(pool, plugins...)
}
