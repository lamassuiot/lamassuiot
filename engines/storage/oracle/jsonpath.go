package oracle

import (
	"strings"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"gorm.io/gorm/clause"
)

// sortJSONPath converts the API's validated sorting path to an Oracle SQL/JSON
// path. It preserves object keys and array steps, including last. The result is
// safe to use as a SQL string literal: the accepted grammar excludes quotes.
// Sorting semantics are implemented by jsonPathOrder.Build below.
func sortJSONPath(path string) (string, error) {
	if _, err := resources.ParseSortJsonPath(path); err != nil {
		return "", err
	}

	var out strings.Builder
	out.WriteByte('$')
	for i := 1; i < len(path); {
		if path[i] == '.' {
			i++
			start := i
			for i < len(path) && path[i] != '.' && path[i] != '[' {
				i++
			}
			out.WriteString(".\"")
			out.WriteString(path[start:i])
			out.WriteByte('"')
		} else {
			start := i
			for path[i] != ']' {
				i++
			}
			i++
			out.WriteString(path[start:i])
		}
	}
	return out.String(), nil
}

// jsonPathOrder sorts JSON values by a text key that orders the JSON types,
// then by the value of JSON numbers. It preserves empty strings separately
// from missing and null values. ISO date
// strings are normalized to a timezone-free timestamp, matching
// PostgreSQL's timestamp cast. Oracle requires SQL/JSON paths to be SQL literals, so this path
// is safe to inline only after sortJSONPath validates its grammar.
type jsonPathOrder struct {
	column clause.Column
	path   string
	desc   bool
	unique orderKeys
}

func (e jsonPathOrder) Build(builder clause.Builder) {
	path, err := sortJSONPath(e.path)
	if err != nil {
		builder.AddError(err)
		return
	}
	pathLiteral := strings.ReplaceAll(path, "'", "''")
	writeValue := func(returning, method string) {
		builder.WriteString("JSON_VALUE(")
		builder.WriteQuoted(e.column)
		builder.WriteString(", ")
		builder.WriteString("'")
		builder.WriteString(pathLiteral)
		builder.WriteString(method)
		builder.WriteString("' RETURNING ")
		builder.WriteString(returning)
		builder.WriteString(" NULL ON EMPTY NULL ON ERROR)")
	}
	writeExists := func(suffix string) {
		builder.WriteString("JSON_EXISTS(")
		builder.WriteQuoted(e.column)
		builder.WriteString(", '")
		builder.WriteString(pathLiteral)
		builder.WriteString(suffix)
		builder.WriteString("')")
	}
	writeTimestampKey := func() {
		builder.WriteString("TO_CHAR(CAST(TO_TIMESTAMP(REPLACE(SUBSTR(")
		writeValue("VARCHAR2(4000)", "")
		builder.WriteString(", 1, 19), 'T', ' ') || '.' || RPAD(SUBSTR(NVL(REGEXP_SUBSTR(")
		writeValue("VARCHAR2(4000)", "")
		builder.WriteString(", '[.]([0-9]+)', 1, 1, NULL, 1), '0'), 1, 9), 9, '0'), 'YYYY-MM-DD HH24:MI:SS.FF9') AS TIMESTAMP(6)), 'YYYY-MM-DD HH24:MI:SS.FF6')")
	}
	// The source PostgreSQL engine sorts extracted JSON text as a lexical key.
	// Carry that key in a CLOB-backed Oracle object with an ORDER method so
	// arrays, objects, and strings longer than VARCHAR2(4000) keep the same
	// ordering rule without truncation.
	builder.WriteString("CASE WHEN ")
	writeExists("")
	builder.WriteString(" AND NOT ")
	writeExists(`?(@.type() == "null")`)
	builder.WriteString(" THEN lamassu_json_sort_key(CASE WHEN ")
	// Without numberOnly(), Oracle implicitly converts JSON strings such as
	// "12" to NUMBER. PostgreSQL only treats JSON numbers as numeric sort keys.
	// All numbers share the text key '0', which places them among the other
	// JSON types as before; the second ORDER BY key orders them by value.
	writeValue("NUMBER", ".numberOnly()")
	builder.WriteString(" IS NOT NULL THEN TO_CLOB('0') WHEN REGEXP_LIKE(")
	writeValue("VARCHAR2(4000)", "")
	builder.WriteString(", '^[0-9]{4}-[0-9]{2}-[0-9]{2}') THEN TO_CLOB(CASE WHEN LENGTH(")
	writeValue("VARCHAR2(4000)", "")
	builder.WriteString(") > 10 THEN ")
	writeTimestampKey()
	// A date-only value gets the same key as a datetime at midnight with a zero
	// fraction, as in PostgreSQL's timestamp cast.
	builder.WriteString(" ELSE TO_CHAR(TO_TIMESTAMP(SUBSTR(")
	writeValue("VARCHAR2(4000)", "")
	builder.WriteString(", 1, 10) || ' 00:00:00', 'YYYY-MM-DD HH24:MI:SS'), 'YYYY-MM-DD HH24:MI:SS') || '.000000' END) WHEN ")
	writeExists(`?(@.type() == "array" || @.type() == "object" )`)
	builder.WriteString(" THEN JSON_QUERY(")
	builder.WriteQuoted(e.column)
	builder.WriteString(", '")
	builder.WriteString(pathLiteral)
	builder.WriteString("' RETURNING CLOB NULL ON EMPTY ERROR ON ERROR) WHEN ")
	writeExists(`?(@.type() == "string" && @.stringOnly() == "" )`)
	builder.WriteString(" THEN TO_CLOB(CHR(1)) ELSE ")
	writeValue("CLOB", "")
	builder.WriteString(" END)")
	builder.WriteString(" ELSE NULL END")
	direction := " ASC NULLS FIRST"
	if e.desc {
		direction = " DESC NULLS LAST"
	}
	builder.WriteString(direction)
	// The value of JSON numbers, NULL for other types. Comparing the numbers
	// themselves orders negatives, decimals and wide numbers correctly.
	builder.WriteString(", ")
	writeValue("NUMBER", ".numberOnly()")
	builder.WriteString(direction)
	if len(e.unique) > 0 {
		builder.WriteString(", ")
		e.unique.Build(builder)
	}
}
