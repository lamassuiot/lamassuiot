package gorm

import (
	"strings"

	authzsdk "github.com/lamassuiot/lamassuiot/v4/connectors/authz/sdk"
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

	// A read view may expose the canonical table as an alias. Qualified references in
	// generated policy SQL must use that alias; the physical schema-qualified name
	// is no longer visible once the FROM relation has been aliased.
	if db.Statement.TableExpr != nil && strings.Contains(strings.ToUpper(db.Statement.TableExpr.SQL), " AS ") {
		from := findWordPos(strings.ToUpper(queryStr), "FROM")
		if from >= 0 {
			fields := strings.Fields(queryStr[from+len("FROM"):])
			if len(fields) > 0 {
				parsed.where = replaceTableQualifier(parsed.where, fields[0], db.Statement.Table)
				for i, join := range parsed.joins {
					parsed.joins[i] = replaceTableQualifier(join, fields[0], db.Statement.Table)
				}
			}
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

// replaceTableQualifier changes identifier qualifiers in generated policy SQL,
// preserving quoted filter values, including escaped quotes inside those values.
func replaceTableQualifier(sql, from, to string) string {
	if from == to {
		return sql
	}
	prefix := from + "."
	var out strings.Builder
	for i := 0; i < len(sql); {
		if sql[i] == '\'' {
			start := i
			i++
			for i < len(sql) {
				if sql[i] == '\'' {
					i++
					if i < len(sql) && sql[i] == '\'' {
						i++
						continue
					}
					break
				}
				i++
			}
			out.WriteString(sql[start:i])
		} else if strings.HasPrefix(sql[i:], prefix) && (i == 0 || (!isIdentChar(sql[i-1]) && sql[i-1] != '.')) {
			out.WriteString(to)
			out.WriteByte('.')
			i += len(prefix)
		} else {
			out.WriteByte(sql[i])
			i++
		}
	}
	return out.String()
}
