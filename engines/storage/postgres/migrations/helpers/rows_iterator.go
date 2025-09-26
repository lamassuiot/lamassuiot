package helpers

import (
	"database/sql"
	"fmt"
	"log"
)

func RowsToMap(rows *sql.Rows) ([]map[string]any, error) {
	// Fetch column names
	columns, err := rows.Columns()
	if err != nil {
		log.Fatalf("Failed to fetch column names: %v", err)
	}

	result := make([]map[string]any, 0)

	// Iterate over the rows
	for rows.Next() {
		// Create a slice of interface{} to hold values for each column
		values := make([]any, len(columns))
		// Create a slice of pointers to hold references to the values
		valuePtrs := make([]any, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		// Scan the row into the value pointers
		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, fmt.Errorf("failed to scan row: %v", err)
		}

		// Create a map to store column name and value
		rowMap := make(map[string]any)
		for i, col := range columns {
			val := values[i]

			// Handle `nil` values
			if b, ok := val.([]byte); ok {
				rowMap[col] = string(b)
			} else {
				rowMap[col] = val
			}
		}

		result = append(result, rowMap)
	}

	// Check for errors encountered during iteration
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error encountered during iteration: %v", err)
	}

	return result, nil
}
