package postgres

import (
	"context"
	"strings"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func newDryRunTenantDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, NewTenantGormPlugin().Initialize(db))
	return db.Session(&gorm.Session{DryRun: true})
}

type testTenantRecord struct {
	ID       string `gorm:"column:id;primaryKey"`
	TenantID string `gorm:"column:tenant_id"`
	Status   string `gorm:"column:status"`
}

func (testTenantRecord) TableName() string {
	return "ca_certificates"
}

func TestTenantGormPlugin_NoOpWithoutTenantInContext(t *testing.T) {
	db := newDryRunTenantDB(t)

	var dest []testTenantRecord
	sql := db.WithContext(context.Background()).Find(&dest).Statement.SQL.String()
	assert.NotContains(t, sql, "tenant_id")
}

func TestTenantGormPlugin_FiltersSelectUpdateDelete(t *testing.T) {
	db := newDryRunTenantDB(t)
	ctx := context.WithValue(context.Background(), core.LamassuContextKeyTenantID, "tenant-alpha")

	t.Run("SELECT on canonical table", func(t *testing.T) {
		var dest []testTenantRecord
		stmt := db.WithContext(ctx).Where("id = ?", "ca-1").Find(&dest).Statement
		sql := stmt.SQL.String()
		assert.Contains(t, sql, "`ca_certificates`.`tenant_id` = ?")
		assert.Contains(t, stmt.Vars, "tenant-alpha")
	})

	t.Run("SELECT on aliased view table", func(t *testing.T) {
		var dest []map[string]any
		stmt := db.WithContext(ctx).Table("certificates_view AS certificates").Find(&dest).Statement
		sql := stmt.SQL.String()
		assert.Contains(t, sql, "`certificates`.`tenant_id` = ?")
		assert.Equal(t, []any{"tenant-alpha"}, stmt.Vars)
	})

	t.Run("UPDATE scopes by tenant_id", func(t *testing.T) {
		stmt := db.WithContext(ctx).Model(&testTenantRecord{}).Where("id = ?", "ca-1").Update("status", "REVOKED").Statement
		sql := stmt.SQL.String()
		assert.Contains(t, sql, "`ca_certificates`.`tenant_id` = ?")
		assert.Contains(t, stmt.Vars, "tenant-alpha")
	})

	t.Run("DELETE scopes by tenant_id", func(t *testing.T) {
		stmt := db.WithContext(ctx).Where("id = ?", "ca-1").Delete(&testTenantRecord{}).Statement
		sql := stmt.SQL.String()
		assert.Contains(t, sql, "`ca_certificates`.`tenant_id` = ?")
		assert.Contains(t, stmt.Vars, "tenant-alpha")
	})
}

func TestTenantGormPlugin_OverridesTenantIDOnCreate(t *testing.T) {
	db := newDryRunTenantDB(t)
	ctx := context.WithValue(context.Background(), core.LamassuContextKeyTenantID, "tenant-alpha")

	rec := &testTenantRecord{
		ID:       "ca-1",
		TenantID: "spoofed-tenant",
		Status:   "ACTIVE",
	}
	stmt := db.WithContext(ctx).Create(rec).Statement
	require.NoError(t, stmt.Error)
	assert.Equal(t, "tenant-alpha", rec.TenantID)
	assert.Contains(t, strings.ToUpper(stmt.SQL.String()), "INSERT INTO")
	assert.Contains(t, stmt.Vars, "tenant-alpha")
	assert.NotContains(t, stmt.Vars, "spoofed-tenant")
}

func TestTenantGormPlugin_StrictModeFailsClosedWithoutTenant(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, NewStrictTenantGormPlugin().Initialize(db))
	dry := db.Session(&gorm.Session{DryRun: true})

	var dest []testTenantRecord
	assert.ErrorIs(t, dry.WithContext(context.Background()).Find(&dest).Error, core.ErrMissingTenantID)
	assert.ErrorIs(t, dry.WithContext(context.Background()).Model(&testTenantRecord{}).Where("id = ?", "ca-1").Update("status", "REVOKED").Error, core.ErrMissingTenantID)
	assert.ErrorIs(t, dry.WithContext(context.Background()).Where("id = ?", "ca-1").Delete(&testTenantRecord{}).Error, core.ErrMissingTenantID)
	assert.ErrorIs(t, dry.WithContext(context.Background()).Create(&testTenantRecord{ID: "ca-1"}).Error, core.ErrMissingTenantID)
}
