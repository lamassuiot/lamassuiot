package upgradecheck

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	lconfig "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/config"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// NewEnv returns an environment that opens a connection per schema on first use and reuses it. Opening a
// connection never migrates the schema.
func NewEnv(logger *logrus.Entry, pg lconfig.PostgresPSEConfig) *Env {
	var mu sync.Mutex
	conns := map[string]*gorm.DB{}
	return &Env{
		Schema: func(schema string) (*gorm.DB, error) {
			mu.Lock()
			defer mu.Unlock()
			if db, ok := conns[schema]; ok {
				return db, nil
			}
			db, err := postgres.CreatePostgresDBConnection(logger, pg, schema)
			if err != nil {
				return nil, fmt.Errorf("connect to schema %s: %w", schema, err)
			}
			conns[schema] = db
			return db, nil
		},
		Engines: map[string]cryptoengines.CryptoEngine{},
	}
}

var ErrNotV38Database = errors.New("upgrade-check only checks 3.8 databases")

// CheckV38Database tells whether the database is a 3.8 one: va.va_role still has crl_subject_key_id_signer and
// va.crl_settings does not exist yet.
func CheckV38Database(ctx context.Context, env *Env) error {
	db, err := env.Schema(postgres.VA_SCHEMA)
	if err != nil {
		return err
	}

	var state struct {
		HasSignerSKI   bool
		HasCRLSettings bool
	}
	err = db.WithContext(ctx).Raw(`SELECT
		EXISTS (SELECT 1 FROM information_schema.columns
			WHERE table_schema = 'va' AND table_name = 'va_role' AND column_name = 'crl_subject_key_id_signer') AS has_signer_ski,
		to_regclass('va.crl_settings') IS NOT NULL AS has_crl_settings`).Scan(&state).Error
	if err != nil {
		return fmt.Errorf("read the va schema: %w", err)
	}

	if state.HasCRLSettings {
		return fmt.Errorf("%w: va.crl_settings exists, so the v4 VA migrations already ran", ErrNotV38Database)
	}
	if !state.HasSignerSKI {
		return fmt.Errorf("%w: va.va_role has no crl_subject_key_id_signer column", ErrNotV38Database)
	}
	return nil
}
