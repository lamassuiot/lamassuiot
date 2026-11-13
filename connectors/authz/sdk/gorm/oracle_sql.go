package gorm

import (
	"strconv"
	"strings"
	"unicode"

	"gorm.io/gorm/clause"
)

// The authorization SQL parser below accepts the structured subset emitted by
// Authz: allow-listed relations, LEFT JOIN equality paths, and bound scalar
// predicates. It rejects every unrecognized construct.
type authzToken struct {
	text    string
	literal bool
	numeric bool
}
type authzEntity struct{ schema, table, primary, view string }

var authzEntities = map[string]authzEntity{
	"principals":         {"", "principals", "id", ""},
	"policies":           {"", "policies", "id", ""},
	"principal_policies": {"", "principal_policies", "id", ""},
	"events":             {"alerts", "events", "event_type", ""},
	"subscriptions":      {"alerts", "subscriptions", "id", ""},
	"ca_certificates":    {"ca", "ca_certificates", "id", ""},
	"certificates":       {"ca", "certificates", "serial_number", "certificates_view"},
	"issuance_profiles":  {"ca", "issuance_profiles", "id", ""},
	"device_groups":      {"devicemanager", "device_groups", "id", ""},
	"devices":            {"devicemanager", "devices", "id", ""},
	"dms":                {"dmsmanager", "dms", "id", ""},
	"kms_keys":           {"kms", "kms_keys", "key_id", ""},
	"va_role":            {"va", "va_role", "ca_ski", ""},
}

func authzTokens(input string) ([]authzToken, error) {
	var out []authzToken
	for i := 0; i < len(input); {
		if input[i] == ' ' || input[i] == '\t' || input[i] == '\n' || input[i] == '\r' {
			i++
			continue
		}
		if input[i] == '\'' {
			i++
			var value strings.Builder
			closed := false
			for i < len(input) {
				if input[i] == '\'' {
					i++
					if i < len(input) && input[i] == '\'' {
						value.WriteByte('\'')
						i++
						continue
					}
					closed = true
					break
				}
				value.WriteByte(input[i])
				i++
			}
			if !closed {
				return nil, ErrAuthorizationUnsupported
			}
			out = append(out, authzToken{text: value.String(), literal: true})
			continue
		}
		if isAuthzNumberStart(input, i) {
			start := i
			if input[i] == '-' {
				i++
			}
			for i < len(input) && input[i] >= '0' && input[i] <= '9' {
				i++
			}
			if i < len(input) && input[i] == '.' {
				i++
				for i < len(input) && input[i] >= '0' && input[i] <= '9' {
					i++
				}
			}
			if i < len(input) && (input[i] == 'e' || input[i] == 'E') {
				i++
				if i < len(input) && (input[i] == '+' || input[i] == '-') {
					i++
				}
				exponentStart := i
				for i < len(input) && input[i] >= '0' && input[i] <= '9' {
					i++
				}
				if exponentStart == i {
					return nil, ErrAuthorizationUnsupported
				}
			}
			if _, err := strconv.ParseFloat(input[start:i], 64); err != nil {
				return nil, ErrAuthorizationUnsupported
			}
			out = append(out, authzToken{text: input[start:i], numeric: true})
			continue
		}
		if strings.ContainsRune("*.,()=<>!", rune(input[i])) {
			start := i
			i++
			if i < len(input) && (input[start] == '<' || input[start] == '>' || input[start] == '!') && input[i] == '=' {
				i++
			} else if input[start] == '<' && i < len(input) && input[i] == '>' {
				i++
			}
			out = append(out, authzToken{text: input[start:i]})
			continue
		}
		if input[i] < 128 && (unicode.IsLetter(rune(input[i])) || unicode.IsDigit(rune(input[i])) || input[i] == '_') {
			start := i
			for i < len(input) && input[i] < 128 && (unicode.IsLetter(rune(input[i])) || unicode.IsDigit(rune(input[i])) || input[i] == '_') {
				i++
			}
			out = append(out, authzToken{text: strings.ToLower(input[start:i])})
			continue
		}
		return nil, ErrAuthorizationUnsupported
	}
	return out, nil
}

func isAuthzNumberStart(input string, i int) bool {
	if i >= len(input) {
		return false
	}
	if input[i] >= '0' && input[i] <= '9' {
		return true
	}
	return input[i] == '-' && i+1 < len(input) && input[i+1] >= '0' && input[i+1] <= '9'
}

type authzParser struct {
	tokens []authzToken
	pos    int
}

func (p *authzParser) peek(value string) bool {
	return p.pos < len(p.tokens) && !p.tokens[p.pos].literal && p.tokens[p.pos].text == value
}

func (p *authzParser) take(value string) bool {
	if p.pos >= len(p.tokens) || p.tokens[p.pos].literal || p.tokens[p.pos].text != value {
		return false
	}
	p.pos++
	return true
}

func (p *authzParser) word() (string, bool) {
	if p.pos >= len(p.tokens) || p.tokens[p.pos].literal || p.tokens[p.pos].numeric {
		return "", false
	}
	value := p.tokens[p.pos].text
	if value == "" || strings.ContainsAny(value, "*.,()=<>!") {
		return "", false
	}
	p.pos++
	return value, true
}

type authorizationPlan struct {
	where clause.Expression
	joins []clause.Join
}

func authorizationTargetsStatement(query, target string) (bool, error) {
	tokens, err := authzTokens(query)
	if err != nil {
		return false, err
	}
	p := authzParser{tokens: tokens}
	if !p.take("select") || !p.take("*") || !p.take("from") {
		return false, ErrAuthorizationUnsupported
	}
	parts, ok := p.qualifiedName()
	if !ok {
		return false, ErrAuthorizationUnsupported
	}
	queryRelation, ok := resolveAuthzRelation(parts)
	if !ok {
		return false, ErrAuthorizationUnsupported
	}
	targetEntity, ok := authzEntityForTarget(target)
	if !ok {
		// Authz predicates belong to their declared root table. A different
		// association preload must not inherit the parent's joins or filters.
		return false, nil
	}
	return queryRelation.schema == targetEntity.schema && queryRelation.table == targetEntity.table, nil
}

type authzRelation struct {
	schema     string
	table      string
	oracleName string
}

var authzRelations = func() map[string]authzRelation {
	relations := make(map[string]authzRelation)
	for _, entity := range authzEntities {
		relations[entity.schema+"."+entity.table] = authzRelation{schema: entity.schema, table: entity.table, oracleName: entity.table}
		if entity.view != "" {
			relations[entity.schema+"."+entity.view] = authzRelation{schema: entity.schema, table: entity.table, oracleName: entity.view}
		}
	}
	return relations
}()

type authzColumnEquality struct {
	left  clause.Column
	right clause.Column
}

type oracleAuthzJoin struct {
	table string
	alias string
	on    clause.Where
}

func (j oracleAuthzJoin) Build(builder clause.Builder) {
	builder.WriteString("LEFT JOIN ")
	builder.WriteQuoted(clause.Table{Name: j.table})
	if j.alias != "" {
		builder.WriteByte(' ')
		builder.WriteQuoted(clause.Table{Name: j.alias, Raw: true})
	}
	if len(j.on.Exprs) > 0 {
		builder.WriteString(" ON ")
		j.on.Build(builder)
	}
}

func (e authzColumnEquality) Build(builder clause.Builder) {
	builder.WriteQuoted(e.left)
	builder.WriteString(" = ")
	builder.WriteQuoted(e.right)
}

// parseAuthorization translates the constrained SQL emitted by Authz into
// structured GORM clauses. Relations and columns are always parsed into
// identifiers; string data becomes bind variables. Unsupported SQL fails
// closed instead of being sent to Oracle or ignored.
func parseAuthorization(query, target string) (authorizationPlan, error) {
	var empty authorizationPlan
	tokens, err := authzTokens(query)
	if err != nil {
		return empty, err
	}
	p := authzParser{tokens: tokens}
	entity, ok := authzEntityForTarget(target)
	if !ok || !p.take("select") || !p.take("*") || !p.take("from") {
		return empty, ErrAuthorizationUnsupported
	}
	rootParts, ok := p.qualifiedName()
	if !ok {
		return empty, ErrAuthorizationUnsupported
	}
	root, ok := resolveAuthzRelation(rootParts)
	if !ok || root.schema != entity.schema || root.table != entity.table {
		return empty, ErrAuthorizationUnsupported
	}
	rootName := strings.Join(rootParts, ".")
	qualifiers := map[string]string{
		rootName:                       root.table,
		root.schema + "." + root.table: root.table,
		root.table:                     root.table,
	}
	if len(rootParts) == 2 {
		qualifiers[rootParts[1]] = root.table
	}
	if p.take("as") {
		alias, valid := p.word()
		if !valid {
			return empty, ErrAuthorizationUnsupported
		}
		qualifiers[alias] = root.table
	} else if p.pos < len(p.tokens) && isAuthzIdentifier(p.tokens[p.pos]) && !isAuthzJoinStart(&p) && !p.peek("where") {
		// Authz emits explicit aliases for views; accept the SQL shorthand too.
		alias, valid := p.word()
		if !valid {
			return empty, ErrAuthorizationUnsupported
		}
		qualifiers[alias] = root.table
	}

	var joins []clause.Join
	for p.take("left") {
		p.take("outer")
		if !p.take("join") {
			return empty, ErrAuthorizationUnsupported
		}
		parts, valid := p.qualifiedName()
		if !valid {
			return empty, ErrAuthorizationUnsupported
		}
		relation, valid := resolveAuthzRelation(parts)
		if !valid {
			return empty, ErrAuthorizationUnsupported
		}
		tableName := strings.Join(parts, ".")
		alias := relation.table
		if p.take("as") {
			alias, valid = p.word()
			if !valid {
				return empty, ErrAuthorizationUnsupported
			}
		} else if p.pos < len(p.tokens) && isAuthzIdentifier(p.tokens[p.pos]) && !p.peek("on") && !isAuthzJoinStart(&p) {
			alias, valid = p.word()
			if !valid {
				return empty, ErrAuthorizationUnsupported
			}
		}
		if _, exists := qualifiers[alias]; exists {
			return empty, ErrAuthorizationUnsupported
		}
		qualifiers[tableName] = alias
		qualifiers[relation.schema+"."+relation.table] = alias
		qualifiers[relation.table] = alias
		qualifiers[alias] = alias
		if !p.take("on") {
			return empty, ErrAuthorizationUnsupported
		}
		var onConditions []clause.Expression
		for {
			left, valid := p.qualifiedColumn(qualifiers)
			if !valid || !p.take("=") {
				return empty, ErrAuthorizationUnsupported
			}
			right, valid := p.qualifiedColumn(qualifiers)
			if !valid {
				return empty, ErrAuthorizationUnsupported
			}
			onConditions = append(onConditions, authzColumnEquality{left: left, right: right})
			if !p.take("and") {
				break
			}
		}
		joins = append(joins, clause.Join{Expression: oracleAuthzJoin{
			table: relation.oracleName,
			alias: alias,
			on:    clause.Where{Exprs: []clause.Expression{clause.And(onConditions...)}},
		}})
	}
	if !p.take("where") {
		return empty, ErrAuthorizationUnsupported
	}
	where, err := p.parseAuthzOr(qualifiers)
	if err != nil || p.pos != len(p.tokens) {
		return empty, ErrAuthorizationUnsupported
	}
	return authorizationPlan{where: where, joins: joins}, nil
}

func authzEntityForTarget(target string) (authzEntity, bool) {
	target = strings.ToLower(strings.TrimSpace(target))
	if i := strings.IndexAny(target, " \t\n"); i >= 0 {
		target = target[:i]
	}
	if i := strings.LastIndexByte(target, '.'); i >= 0 {
		target = target[i+1:]
	}
	if entity, ok := authzEntities[target]; ok {
		return entity, true
	}
	for _, entity := range authzEntities {
		if target == entity.table || (entity.view != "" && target == entity.view) {
			return entity, true
		}
	}
	return authzEntity{}, false
}

func resolveAuthzRelation(parts []string) (authzRelation, bool) {
	if len(parts) == 1 {
		var match authzRelation
		found := false
		for _, relation := range authzRelations {
			if relation.oracleName == parts[0] {
				if found && match.schema != relation.schema {
					return authzRelation{}, false
				}
				match, found = relation, true
			}
		}
		return match, found
	}
	if len(parts) == 2 {
		relation, ok := authzRelations[parts[0]+"."+parts[1]]
		return relation, ok
	}
	return authzRelation{}, false
}

func isAuthzIdentifier(token authzToken) bool {
	return !token.literal && !token.numeric && token.text != "" && !strings.ContainsAny(token.text, "*.,()=<>!")
}

var oracleBooleanColumns = map[string]struct{}{
	"has_private_key": {}, "is_ca": {}, "crl_regenerate_on_revoke": {}, "sign_as_ca": {},
	"honor_key_usage": {}, "honor_extended_key_usages": {}, "honor_subject": {}, "honor_extensions": {},
	"crypto_enforcement_enabled": {}, "crypto_enforcement_allow_rsa_keys": {}, "crypto_enforcement_allow_ecdsa_keys": {},
}

func authzLiteralValue(token authzToken, column clause.Column) (any, error) {
	if _, isBoolean := oracleBooleanColumns[strings.ToLower(column.Name)]; isBoolean {
		switch strings.ToLower(token.text) {
		case "true":
			if token.literal || !token.numeric {
				return int64(1), nil
			}
		case "false":
			if token.literal || !token.numeric {
				return int64(0), nil
			}
		}
		return nil, ErrAuthorizationUnsupported
	}
	if token.numeric {
		value, err := strconv.ParseFloat(token.text, 64)
		if err != nil {
			return nil, ErrAuthorizationUnsupported
		}
		return value, nil
	}
	if token.literal {
		return token.text, nil
	}
	return nil, ErrAuthorizationUnsupported
}

func isAuthzJoinStart(p *authzParser) bool {
	if p.pos >= len(p.tokens) {
		return false
	}
	return p.tokens[p.pos].text == "left"
}

func (p *authzParser) qualifiedName() ([]string, bool) {
	first, ok := p.word()
	if !ok {
		return nil, false
	}
	parts := []string{first}
	for p.take(".") {
		part, valid := p.word()
		if !valid {
			return nil, false
		}
		parts = append(parts, part)
	}
	if len(parts) > 2 {
		return nil, false
	}
	return parts, true
}

func (p *authzParser) qualifiedColumn(qualifiers map[string]string) (clause.Column, bool) {
	first, ok := p.word()
	if !ok {
		return clause.Column{}, false
	}
	parts := []string{first}
	for p.take(".") {
		part, valid := p.word()
		if !valid {
			return clause.Column{}, false
		}
		parts = append(parts, part)
		if len(parts) > 3 {
			return clause.Column{}, false
		}
	}
	if len(parts) < 2 {
		return clause.Column{}, false
	}
	qualifier := strings.Join(parts[:len(parts)-1], ".")
	table, ok := qualifiers[qualifier]
	if !ok {
		return clause.Column{}, false
	}
	return clause.Column{Table: table, Name: parts[len(parts)-1]}, true
}

func (p *authzParser) parseAuthzOr(qualifiers map[string]string) (clause.Expression, error) {
	left, err := p.parseAuthzAnd(qualifiers)
	for err == nil && p.take("or") {
		var right clause.Expression
		right, err = p.parseAuthzAnd(qualifiers)
		if err == nil {
			left = clause.Or(left, right)
		}
	}
	return left, err
}

func (p *authzParser) parseAuthzAnd(qualifiers map[string]string) (clause.Expression, error) {
	left, err := p.parseAuthzPrimary(qualifiers)
	for err == nil && p.take("and") {
		var right clause.Expression
		right, err = p.parseAuthzPrimary(qualifiers)
		if err == nil {
			left = clause.And(left, right)
		}
	}
	return left, err
}

func (p *authzParser) parseAuthzPrimary(qualifiers map[string]string) (clause.Expression, error) {
	if p.take("(") {
		expression, err := p.parseAuthzOr(qualifiers)
		if err != nil || !p.take(")") {
			return nil, ErrAuthorizationUnsupported
		}
		return expression, nil
	}
	if p.take("1") {
		if !p.take("=") {
			return nil, ErrAuthorizationUnsupported
		}
		if p.take("0") {
			return clause.Expr{SQL: "1 = 0"}, nil
		}
		if p.take("1") {
			return clause.Expr{SQL: "1 = 1"}, nil
		}
		return nil, ErrAuthorizationUnsupported
	}
	column, ok := p.qualifiedColumn(qualifiers)
	if !ok {
		return nil, ErrAuthorizationUnsupported
	}
	if p.take("is") {
		if p.take("not") {
			if !p.take("null") {
				return nil, ErrAuthorizationUnsupported
			}
			return clause.Neq{Column: column, Value: nil}, nil
		}
		if !p.take("null") {
			return nil, ErrAuthorizationUnsupported
		}
		return clause.Eq{Column: column, Value: nil}, nil
	}
	if p.take("in") {
		if !p.take("(") {
			return nil, ErrAuthorizationUnsupported
		}
		values, err := p.authzLiterals(column)
		if err != nil || !p.take(")") {
			return nil, ErrAuthorizationUnsupported
		}
		return clause.IN{Column: column, Values: values}, nil
	}
	if p.take("like") {
		if p.pos >= len(p.tokens) || !p.tokens[p.pos].literal {
			return nil, ErrAuthorizationUnsupported
		}
		value := p.tokens[p.pos].text
		p.pos++
		return clause.Like{Column: column, Value: value}, nil
	}
	if p.pos < len(p.tokens) {
		op := p.tokens[p.pos].text
		if op == "=" || op == "!=" || op == "<>" || op == ">" || op == ">=" || op == "<" || op == "<=" {
			p.pos++
			if p.pos >= len(p.tokens) {
				return nil, ErrAuthorizationUnsupported
			}
			value, err := authzLiteralValue(p.tokens[p.pos], column)
			if err != nil {
				return nil, err
			}
			p.pos++
			switch op {
			case "=":
				return clause.Eq{Column: column, Value: value}, nil
			case "!=", "<>":
				return clause.Neq{Column: column, Value: value}, nil
			case ">":
				return clause.Gt{Column: column, Value: value}, nil
			case ">=":
				return clause.Gte{Column: column, Value: value}, nil
			case "<":
				return clause.Lt{Column: column, Value: value}, nil
			case "<=":
				return clause.Lte{Column: column, Value: value}, nil
			}
		}
	}
	return nil, ErrAuthorizationUnsupported
}

func (p *authzParser) authzLiterals(column clause.Column) ([]any, error) {
	var values []any
	for {
		if p.pos >= len(p.tokens) {
			return nil, ErrAuthorizationUnsupported
		}
		value, err := authzLiteralValue(p.tokens[p.pos], column)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
		p.pos++
		if !p.take(",") {
			return values, nil
		}
	}
}
