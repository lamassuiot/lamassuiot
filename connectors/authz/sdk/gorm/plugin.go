package gorm

import (
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

	// Add AST to the query
	AddASTToQuery(db, result, queryStr)
}
