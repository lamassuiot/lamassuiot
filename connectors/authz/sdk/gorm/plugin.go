package gorm

import (
	"strings"

	authzsdk "github.com/lamassuiot/authz/sdk"
	"gorm.io/gorm"
)

// AuthzGormPlugin is a GORM plugin that injects authorization queries from context
type AuthzGormPlugin struct {
}

func NewAuthzGormPlugin() *AuthzGormPlugin { return &AuthzGormPlugin{} }

// Name returns the plugin name
func (p *AuthzGormPlugin) Name() string {
	return "authz-plugin"
}

// Initialize initializes the plugin with GORM
func (p *AuthzGormPlugin) Initialize(db *gorm.DB) error {
	return db.Callback().Query().Before("gorm:query").Register("authz:inject", p.injectAuthzQuery)
}

// injectAuthzQuery is the callback that injects the authorization query from context
func (p *AuthzGormPlugin) injectAuthzQuery(db *gorm.DB) {
	ctx := db.Statement.Context
	if ctx == nil {
		return
	}

	authzQuery := ctx.Value(authzsdk.AuthzQueryKey)
	if authzQuery == nil {
		return
	}

	queryStr, ok := authzQuery.(string)
	if !ok {
		return
	}

	if queryStr == "" {
		return
	}

	parsed := parseAuthzSQL(queryStr)

	// Only inject when the current statement targets the same table as the authz SQL.
	// GORM runs preload sub-queries (for associations) in the same context using
	// different tables. Injecting a condition meant for table A into a query against
	// table B would produce a "missing FROM-clause entry" SQL error.
	if db.Statement != nil && db.Statement.Table != "" {
		if parsed.fromTable != "" && !tableNamesMatch(db.Statement.Table, parsed.fromTable) {
			return
		}
	}

	AddASTToQuery(db, parsed)
}

// tableNamesMatch compares two table name strings, ignoring any schema prefix.
func tableNamesMatch(a, b string) bool {
	unqualify := func(s string) string {
		if idx := strings.LastIndex(s, "."); idx >= 0 {
			return s[idx+1:]
		}
		return s
	}
	return unqualify(a) == unqualify(b)
}
