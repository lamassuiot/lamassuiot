package transport

import (
	"fmt"
	"strings"

	"gorm.io/gorm"
)

const schemaKey = "lamassu_schema"

// IsRDSDataAPI reports whether db uses the Data API transport.
func IsRDSDataAPI(db *gorm.DB) bool {
	_, ok := db.Get(schemaKey)
	return ok
}

// QualifiedTable returns a schema-qualified table name when required by the transport.
func QualifiedTable(db *gorm.DB, tableName string) string {
	if strings.Contains(tableName, ".") {
		return tableName
	}

	schemaName, ok := db.Get(schemaKey)
	if !ok {
		return tableName
	}

	return fmt.Sprintf("%s.%s", schemaName, tableName)
}
