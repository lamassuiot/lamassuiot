package postgres

import (
	"reflect"
	"strings"

	"github.com/lamassuiot/lamassuiot/v4/core"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// TenantGormPlugin injects tenant_id isolation into GORM queries, updates, deletes,
// and creates whenever LamassuContextKeyTenantID is present in the statement context.
// When RequireTenant is true, operations without a tenant_id in context fail closed
// with core.ErrMissingTenantID.
type TenantGormPlugin struct {
	RequireTenant bool
}

func NewTenantGormPlugin() *TenantGormPlugin {
	return &TenantGormPlugin{}
}

func NewStrictTenantGormPlugin() *TenantGormPlugin {
	return &TenantGormPlugin{RequireTenant: true}
}

func (p *TenantGormPlugin) Name() string {
	return "tenant-isolation-plugin"
}

func (p *TenantGormPlugin) Initialize(db *gorm.DB) error {
	if err := db.Callback().Query().Before("gorm:query").Register("tenant:filter_query", p.injectTenantFilter); err != nil {
		return err
	}
	if err := db.Callback().Row().Before("gorm:row").Register("tenant:filter_row", p.injectTenantFilter); err != nil {
		return err
	}
	if err := db.Callback().Update().Before("gorm:update").Register("tenant:filter_update", p.injectTenantFilter); err != nil {
		return err
	}
	if err := db.Callback().Delete().Before("gorm:delete").Register("tenant:filter_delete", p.injectTenantFilter); err != nil {
		return err
	}
	if err := db.Callback().Create().Before("gorm:create").Register("tenant:set_create", p.injectTenantOnCreate); err != nil {
		return err
	}
	return nil
}

func (p *TenantGormPlugin) injectTenantFilter(db *gorm.DB) {
	if db.Statement == nil {
		return
	}
	tenantID, ok := core.TenantIDFromContext(db.Statement.Context)
	if !ok {
		if p.RequireTenant {
			_ = db.AddError(core.ErrMissingTenantID)
		}
		return
	}

	col := clause.Column{
		Table: resolveTableRef(db.Statement.Table),
		Name:  "tenant_id",
	}
	db.Statement.AddClause(clause.Where{
		Exprs: []clause.Expression{
			clause.Eq{Column: col, Value: tenantID},
		},
	})
}

func (p *TenantGormPlugin) injectTenantOnCreate(db *gorm.DB) {
	if db.Statement == nil {
		return
	}
	tenantID, ok := core.TenantIDFromContext(db.Statement.Context)
	if !ok {
		if p.RequireTenant {
			_ = db.AddError(core.ErrMissingTenantID)
		}
		return
	}

	if m, isMap := db.Statement.Dest.(map[string]any); isMap {
		m["tenant_id"] = tenantID
		return
	}

	if db.Statement.Schema == nil {
		return
	}
	field := db.Statement.Schema.LookUpField("tenant_id")
	if field == nil {
		return
	}

	rv := db.Statement.ReflectValue
	switch rv.Kind() {
	case reflect.Slice, reflect.Array:
		for i := 0; i < rv.Len(); i++ {
			_ = field.Set(db.Statement.Context, rv.Index(i), tenantID)
		}
	case reflect.Struct:
		_ = field.Set(db.Statement.Context, rv, tenantID)
	}
}

func resolveTableRef(table string) string {
	table = strings.TrimSpace(table)
	if table == "" {
		return ""
	}
	upper := strings.ToUpper(table)
	if idx := strings.Index(upper, " AS "); idx >= 0 {
		return strings.TrimSpace(table[idx+4:])
	}
	if idx := strings.LastIndex(table, "."); idx >= 0 {
		return strings.TrimSpace(table[idx+1:])
	}
	return table
}
