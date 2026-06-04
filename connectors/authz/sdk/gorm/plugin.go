package gorm

import (
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"
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
	// Register callback for query operations
	return db.Callback().Query().Before("gorm:query").Register("authz:inject", p.injectAuthzQuery)
}

// injectAuthzQuery is the callback that injects the authorization query from context
func (p *AuthzGormPlugin) injectAuthzQuery(db *gorm.DB) {
	ctx := db.Statement.Context
	if ctx == nil {
		return
	}

	// Get the authz query from context
	authzQuery := ctx.Value("authz_query")
	if authzQuery == nil {
		return
	}

	// Parse the query string
	queryStr, ok := authzQuery.(string)
	if !ok {
		return
	}

	if queryStr == "" {
		return
	}

	// Parse the SQL into AST
	result, err := pg_query.Parse(queryStr)
	if err != nil {
		// Silently skip if parsing fails
		return
	}

	// Only inject when the current statement targets the same table as the authz SQL.
	// GORM runs preload sub-queries (for associations) in the same context, using
	// different tables. Injecting an authz condition meant for table A into a query
	// against table B would produce a "missing FROM-clause entry" SQL error.
	if db.Statement != nil && db.Statement.Table != "" {
		authzTable := extractFromTable(result)
		if authzTable != "" && !tableNamesMatch(db.Statement.Table, authzTable) {
			return
		}
	}

	// Add AST to the query
	AddASTToQuery(db, result, queryStr)
}

// extractFromTable returns the unqualified table name from the first FROM entry of the parsed SQL.
func extractFromTable(ast *pg_query.ParseResult) string {
	if ast == nil || len(ast.Stmts) == 0 {
		return ""
	}
	sel := ast.Stmts[0].GetStmt().GetSelectStmt()
	if sel == nil || len(sel.FromClause) == 0 {
		return ""
	}
	rv := sel.FromClause[0].GetRangeVar()
	if rv == nil {
		return ""
	}
	return rv.Relname
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
