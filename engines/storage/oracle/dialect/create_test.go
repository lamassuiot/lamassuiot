package dialect

import (
	"database/sql"
	"strings"
	"testing"

	"gorm.io/gorm"
)

type createProbe struct {
	ID   uint `gorm:"primaryKey;autoIncrement"`
	Name string
}

func TestCreateRejectsSlicesBeforeInsert(t *testing.T) {
	db, err := gorm.Open(Dialector{Conn: &sql.DB{}}, &gorm.Config{DryRun: true, DisableAutomaticPing: true, SkipDefaultTransaction: true})
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]any{
		"one-element slice": &[]createProbe{{Name: "a"}},
		"array":             &[1]createProbe{{Name: "a"}},
	} {
		t.Run(name, func(t *testing.T) {
			tx := db.Create(value)
			if tx.Error == nil || !strings.Contains(tx.Error.Error(), "create each row separately") {
				t.Fatalf("create error = %v, want a rejection", tx.Error)
			}
			if sql := tx.Statement.SQL.String(); sql != "" {
				t.Fatalf("rejected create built SQL %q", sql)
			}
		})
	}
}

func TestCreateStructReturnsGeneratedValues(t *testing.T) {
	db, err := gorm.Open(Dialector{Conn: &sql.DB{}}, &gorm.Config{DryRun: true, DisableAutomaticPing: true, SkipDefaultTransaction: true})
	if err != nil {
		t.Fatal(err)
	}
	tx := db.Create(&createProbe{Name: "a"})
	if tx.Error != nil {
		t.Fatal(tx.Error)
	}
	if sql := tx.Statement.SQL.String(); !strings.Contains(sql, `RETURNING "ID" INTO`) {
		t.Fatalf("struct create SQL %q does not return the generated ID", sql)
	}
}
