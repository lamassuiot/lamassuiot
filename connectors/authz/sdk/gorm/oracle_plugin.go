package gorm

import (
	"errors"
	"fmt"

	authzsdk "github.com/lamassuiot/lamassuiot/v4/connectors/authz/sdk"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ErrAuthorizationUnsupported prevents authorization SQL outside the
// translated Oracle-safe subset from being silently ignored.
var ErrAuthorizationUnsupported = errors.New("Authz cannot translate this authorization filter for Oracle")

func applyAuthorization(tx *gorm.DB) {
	if tx.Statement == nil || tx.Statement.Context == nil {
		return
	}
	value := tx.Statement.Context.Value(authzsdk.AuthzQueryKey)
	if value == nil {
		return
	}
	query, ok := value.(string)
	if !ok {
		tx.AddError(ErrAuthorizationUnsupported)
		return
	}
	if query == "" {
		// The Authz GORM plugin treats an empty generated query as no filter.
		return
	}
	// GORM does not merge clauses into SQL supplied through Raw. Accepting an
	// authorization predicate here would therefore execute the unfiltered SQL.
	if tx.Statement.SQL.Len() != 0 {
		tx.AddError(fmt.Errorf("%w: prebuilt SQL", ErrAuthorizationUnsupported))
		return
	}
	matches, err := authorizationTargetsStatement(query, tx.Statement.Table)
	if err != nil {
		tx.AddError(err)
		return
	}
	if !matches {
		// GORM runs association preloads in the same context as the parent
		// query. The Authz predicate only applies to its declared root table.
		return
	}
	plan, err := parseAuthorization(query, tx.Statement.Table)
	if err != nil {
		tx.AddError(err)
		return
	}
	if len(plan.joins) != 0 {
		tx.Statement.AddClause(clause.From{Joins: plan.joins})
	}
	tx.Statement.AddClause(clause.Where{Exprs: []clause.Expression{plan.where}})
}

type OracleAuthzGormPlugin struct{}

var _ gorm.Plugin = (*OracleAuthzGormPlugin)(nil)

// NewOracleAuthzGormPlugin creates the Oracle-specific Authz GORM plugin.
func NewOracleAuthzGormPlugin() *OracleAuthzGormPlugin { return &OracleAuthzGormPlugin{} }

func (*OracleAuthzGormPlugin) Name() string { return "oracle-authz-plugin" }

func (*OracleAuthzGormPlugin) Initialize(db *gorm.DB) error {
	queryGuard := applyAuthorization
	guard := func(tx *gorm.DB) {
		if tx.Statement != nil && tx.Statement.Context != nil && tx.Statement.Context.Value(authzsdk.AuthzQueryKey) != nil {
			tx.AddError(ErrAuthorizationUnsupported)
		}
	}
	if err := db.Callback().Query().Before("*").Register("oracle:authorization_guard", queryGuard); err != nil {
		return err
	}
	for _, register := range []func(string, func(*gorm.DB)) error{
		db.Callback().Row().Before("*").Register,
		db.Callback().Raw().Before("*").Register,
		db.Callback().Create().Before("*").Register,
		db.Callback().Update().Before("*").Register,
		db.Callback().Delete().Before("*").Register,
	} {
		if err := register("oracle:authorization_guard", guard); err != nil {
			return err
		}
	}
	return nil
}
