package dialect

import (
	"database/sql"
	"fmt"
	"reflect"

	"gorm.io/gorm"
	"gorm.io/gorm/callbacks"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/schema"
)

// Oracle returns generated values via RETURNING ... INTO bind variables.
// Multi-row creates and conflict clauses require different SQL and are
// rejected until implemented; they must never silently lose rows.
func create(db *gorm.DB) {
	if db.Error != nil {
		return
	}
	stmt := db.Statement
	if _, ok := stmt.Clauses["ON CONFLICT"]; ok {
		db.AddError(fmt.Errorf("oracle dialect: ON CONFLICT is not supported"))
		return
	}
	if _, ok := stmt.Clauses["RETURNING"]; ok {
		db.AddError(fmt.Errorf("oracle dialect: explicit RETURNING is not supported"))
		return
	}
	values := callbacks.ConvertToCreateValues(stmt)
	if len(values.Values) != 1 {
		db.AddError(fmt.Errorf("oracle dialect: expected one row, got %d", len(values.Values)))
		return
	}
	stmt.AddClauseIfNotExists(clause.Insert{})
	stmt.AddClause(values)
	stmt.Build("INSERT", "VALUES")

	var fields []*schema.Field
	var destinations []reflect.Value
	if stmt.Schema != nil {
		for _, field := range stmt.Schema.FieldsWithDefaultDBValue {
			if !field.Readable {
				continue
			}
			fields = append(fields, field)
			destinations = append(destinations, reflect.New(field.FieldType))
		}
	}
	if len(fields) > 0 {
		stmt.WriteString(" RETURNING ")
		for i, field := range fields {
			if i > 0 {
				stmt.WriteByte(',')
			}
			stmt.WriteQuoted(clause.Column{Name: field.DBName})
		}
		stmt.WriteString(" INTO ")
		for i, dest := range destinations {
			if i > 0 {
				stmt.WriteByte(',')
			}
			stmt.AddVar(stmt, sql.Out{Dest: dest.Interface()})
		}
	}
	if db.DryRun || db.Error != nil {
		return
	}
	result, err := stmt.ConnPool.ExecContext(stmt.Context, stmt.SQL.String(), stmt.Vars...)
	if db.AddError(err) != nil {
		return
	}
	db.RowsAffected, _ = result.RowsAffected()
	if stmt.Result != nil {
		stmt.Result.Result = result
		stmt.Result.RowsAffected = db.RowsAffected
	}
	for i, field := range fields {
		if err := field.Set(stmt.Context, stmt.ReflectValue, destinations[i].Elem().Interface()); err != nil {
			db.AddError(err)
			return
		}
	}
}
