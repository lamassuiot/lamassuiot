package oracle

import "gorm.io/gorm/clause"

// Oracle orders character data by the session's NLS_SORT, which the driver
// derives from the client's NLS_LANGUAGE (SPANISH, for example, selects a
// linguistic sort). Keyset pagination needs ORDER BY and its comparisons to
// agree, and results should match PostgreSQL's binary ("C") ordering. Rather
// than altering the session, character columns are ordered and compared via
// NLSSORT(..., 'NLS_SORT=BINARY'). NLSSORT returns RAW, which always compares
// bytewise, so the keyset predicates are also independent of NLS_COMP.
//
// NLSSORT must not wrap numeric or temporal columns: it would convert them to
// text and order them lexically. Only the columns listed here are wrapped;
// TestTextSortColumnsMatchMigrations keeps this list in sync with the schema.
var textSortColumns = map[string]struct{}{
	// Identifiers and keyset columns.
	"id": {}, "serial_number": {}, "key_id": {}, "engine_id": {}, "event_type": {}, "ca_id": {},
	// Certificates and CAs.
	"subject_key_id": {}, "authority_key_id": {}, "status": {}, "key_meta_type": {}, "key_meta_strength": {},
	"subject_common_name": {}, "subject_organization": {}, "subject_organization_unit": {}, "subject_country": {}, "subject_state": {}, "subject_locality": {},
	"issuer_common_name": {}, "issuer_organization": {}, "issuer_organization_unit": {}, "issuer_country": {}, "issuer_state": {}, "issuer_locality": {},
	"revocation_reason": {}, "type": {}, "issuer_meta_serial_number": {}, "issuer_meta_id": {}, "profile_id": {},
	// KMS, devices, DMS, groups, alerts and CRL settings.
	"name": {}, "algorithm": {}, "icon_color": {}, "dms_owner": {}, "device_id": {}, "source": {}, "parent_id": {}, "user_id": {},
	"legacy_ski": {},
}

func isTextSortColumn(name string) bool {
	_, ok := textSortColumns[name]
	return ok
}

// orderKey is one ORDER BY term over a plain column.
type orderKey struct {
	column clause.Column
	desc   bool
}

func newOrderKey(table, name string, desc bool) orderKey {
	return orderKey{column: clause.Column{Table: table, Name: name}, desc: desc}
}

func (k orderKey) binary() bool { return isTextSortColumn(k.column.Name) }

func (k orderKey) writeOperand(builder clause.Builder) {
	if !k.binary() {
		builder.WriteQuoted(k.column)
		return
	}
	builder.WriteString("NLSSORT(")
	builder.WriteQuoted(k.column)
	builder.WriteString(", 'NLS_SORT=BINARY')")
}

// writeValue renders a keyset bound comparable with writeOperand. For text
// columns the bound is UTL_RAW.CONCAT(NLSSORT(?, 'NLS_SORT=BINARY')): Oracle
// rewrites NLSSORT(col, BINARY) > NLSSORT(?, BINARY) as col > ?, which no
// longer matches the binary sort index, so every page would scan the index
// from its start. The single-argument CONCAT returns the same RAW value but
// prevents that rewrite, giving an index range scan that stops after the page.
func (k orderKey) writeValue(builder clause.Builder, value any) {
	if !k.binary() {
		builder.AddVar(builder, value)
		return
	}
	builder.WriteString("UTL_RAW.CONCAT(NLSSORT(")
	builder.AddVar(builder, value)
	builder.WriteString(", 'NLS_SORT=BINARY'))")
}

// orderKeys renders a comma-separated ORDER BY list. Use it as the
// Expression of clause.OrderBy.
type orderKeys []orderKey

func (keys orderKeys) Build(builder clause.Builder) {
	for i, key := range keys {
		if i > 0 {
			builder.WriteString(", ")
		}
		key.writeOperand(builder)
		if key.desc {
			builder.WriteString(" DESC")
		}
	}
}

// keysetAfter selects rows strictly after values in the ascending order of
// keys. It uses a lexicographic expansion, which also works on Oracle releases
// without support for comparing tuple expressions:
// (k1 > v1) OR (k1 = v1 AND k2 > v2) OR ...
// With several keys, a redundant leading k1 >= v1 gives the optimizer a range
// predicate on the first column of the binary sort index.
type keysetAfter struct {
	keys   []orderKey
	values []any
}

func (e keysetAfter) Build(builder clause.Builder) {
	if len(e.keys) > 1 {
		e.keys[0].writeOperand(builder)
		builder.WriteString(" >= ")
		e.keys[0].writeValue(builder, e.values[0])
		builder.WriteString(" AND ")
	}
	builder.WriteByte('(')
	for i := range e.keys {
		if i > 0 {
			builder.WriteString(" OR ")
		}
		builder.WriteByte('(')
		for j := 0; j < i; j++ {
			e.keys[j].writeOperand(builder)
			builder.WriteString(" = ")
			e.keys[j].writeValue(builder, e.values[j])
			builder.WriteString(" AND ")
		}
		e.keys[i].writeOperand(builder)
		builder.WriteString(" > ")
		e.keys[i].writeValue(builder, e.values[i])
		builder.WriteByte(')')
	}
	builder.WriteByte(')')
}
