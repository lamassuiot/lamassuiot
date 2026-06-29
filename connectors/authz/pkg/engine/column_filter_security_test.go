package engine

import (
	"strings"
	"testing"

	"github.com/lamassuiot/lamassuiot/connectors/authz/v3/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// schemaWithFilterable builds a minimal SchemaDefinition exposing the given
// filterable columns, for exercising column-filter SQL generation directly.
func schemaWithFilterable(fields ...FilterableField) *SchemaDefinition {
	return &SchemaDefinition{
		PrimaryKeys: []string{"id"},
		EntityType:  "device",
		TableName:   "devices",
		SchemaName:  "public",
		Filterable:  fields,
	}
}

func TestSQLStringLiteral_EscapesSingleQuotes(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "device-42", "'device-42'"},
		{"single quote", "O'Brien", "'O''Brien'"},
		{"sql injection attempt", "x'; DROP TABLE devices;--", "'x''; DROP TABLE devices;--'"},
		{"multiple quotes", "a'b'c", "'a''b''c'"},
		{"empty", "", "''"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sqlStringLiteral(tc.in)
			assert.Equal(t, tc.want, got)
			// The closing quote of the literal must never be terminable by the
			// payload: every embedded quote is doubled.
			assert.Equal(t, 0, strings.Count(got, "'")%2, "quotes must be balanced/escaped")
		})
	}
}

func TestFormatColumnFilterValue(t *testing.T) {
	tests := []struct {
		name    string
		in      interface{}
		want    string
		wantErr bool
	}{
		{"string", "abc", "'abc'", false},
		{"string with quote", "a'b", "'a''b'", false},
		{"bool true", true, "true", false},
		{"bool false", false, "false", false},
		{"float integer", float64(42), "42", false},
		{"float decimal", 3.5, "3.5", false},
		{"array of strings", []interface{}{"a", "b"}, "('a', 'b')", false},
		{"array mixed", []interface{}{"a", float64(2)}, "('a', 2)", false},
		{"unsupported type int", 5, "", true},
		{"unsupported type nil", nil, "", true},
		{"array with unsupported element", []interface{}{"a", 5}, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := formatColumnFilterValue(tc.in)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestBuildColumnFilterConditions_EscapesInjectionInValue(t *testing.T) {
	schema := schemaWithFilterable(FilterableField{Column: "name", Type: "string"})
	filters := []models.ColumnFilter{
		{Column: "name", Operator: "eq", Value: "x'; DROP TABLE devices;--"},
	}

	cond, err := buildColumnFilterConditions(schema, filters)
	require.NoError(t, err)

	// The malicious payload must be fully contained within an escaped string
	// literal — never break out into executable SQL.
	assert.Equal(t, "devices.name = 'x''; DROP TABLE devices;--'", cond)
}

func TestBuildColumnFilterConditions_MultipleFiltersAreANDed(t *testing.T) {
	schema := schemaWithFilterable(
		FilterableField{Column: "name", Type: "string"},
		FilterableField{Column: "active", Type: "bool"},
	)
	filters := []models.ColumnFilter{
		{Column: "name", Operator: "like", Value: "dev%"},
		{Column: "active", Operator: "eq", Value: true},
	}

	cond, err := buildColumnFilterConditions(schema, filters)
	require.NoError(t, err)
	assert.Equal(t, "devices.name LIKE 'dev%' AND devices.active = true", cond)
}

func TestBuildColumnFilterConditions_InOperatorWithArray(t *testing.T) {
	schema := schemaWithFilterable(FilterableField{Column: "id", Type: "string"})
	filters := []models.ColumnFilter{
		{Column: "id", Operator: "in", Value: []interface{}{"a", "b'c"}},
	}

	cond, err := buildColumnFilterConditions(schema, filters)
	require.NoError(t, err)
	assert.Equal(t, "devices.id IN ('a', 'b''c')", cond)
}

func TestBuildColumnFilterConditions_RejectsNonFilterableColumn(t *testing.T) {
	schema := schemaWithFilterable(FilterableField{Column: "name", Type: "string"})
	filters := []models.ColumnFilter{
		{Column: "secret_column", Operator: "eq", Value: "x"},
	}

	_, err := buildColumnFilterConditions(schema, filters)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not declared as filterable")
}

func TestBuildColumnFilterConditions_RejectsTypeMismatch(t *testing.T) {
	schema := schemaWithFilterable(FilterableField{Column: "name", Type: "string"})
	filters := []models.ColumnFilter{
		{Column: "name", Type: "int", Operator: "eq", Value: "x"},
	}

	_, err := buildColumnFilterConditions(schema, filters)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "type")
}

func TestBuildColumnFilterConditions_RejectsUnsupportedOperator(t *testing.T) {
	schema := schemaWithFilterable(FilterableField{Column: "name", Type: "string"})
	filters := []models.ColumnFilter{
		{Column: "name", Operator: "regex", Value: "x"},
	}

	_, err := buildColumnFilterConditions(schema, filters)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported operator")
}

func TestBuildColumnFilterConditions_RejectsUnsupportedValueType(t *testing.T) {
	schema := schemaWithFilterable(FilterableField{Column: "name", Type: "string"})
	filters := []models.ColumnFilter{
		{Column: "name", Operator: "eq", Value: 5}, // int is not a JSON-decoded type
	}

	_, err := buildColumnFilterConditions(schema, filters)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported filter value type")
}

func TestBuildColumnFilterConditions_EmptyReturnsEmpty(t *testing.T) {
	schema := schemaWithFilterable(FilterableField{Column: "name", Type: "string"})

	cond, err := buildColumnFilterConditions(schema, nil)
	require.NoError(t, err)
	assert.Equal(t, "", cond)
}

func TestEntityKeyCondition_SinglePK_EscapesInjection(t *testing.T) {
	schema := &SchemaDefinition{PrimaryKeys: []string{"id"}, EntityType: "device", TableName: "devices", SchemaName: "public"}

	cond, err := schema.EntityKeyCondition(map[string]string{"id": "x'; DROP TABLE devices;--"}, "devices")
	require.NoError(t, err)
	assert.Equal(t, "devices.id = 'x''; DROP TABLE devices;--'", cond)
}

func TestEntityKeyCondition_CompositePK_SortedAndEscaped(t *testing.T) {
	schema := &SchemaDefinition{PrimaryKeys: []string{"tenant_id", "device_id"}, EntityType: "device", TableName: "devices", SchemaName: "public"}

	cond, err := schema.EntityKeyCondition(map[string]string{"device_id": "d'1", "tenant_id": "t1"}, "devices")
	require.NoError(t, err)
	// Columns are emitted in sorted order (device_id before tenant_id) for determinism.
	assert.Equal(t, "devices.device_id = 'd''1' AND devices.tenant_id = 't1'", cond)
}

func TestEntityKeyCondition_RejectsInvalidKey(t *testing.T) {
	schema := &SchemaDefinition{PrimaryKeys: []string{"id"}, EntityType: "device", TableName: "devices", SchemaName: "public"}

	_, err := schema.EntityKeyCondition(map[string]string{"wrong": "x"}, "devices")
	require.Error(t, err)
}

func TestValidateEntityKey(t *testing.T) {
	composite := &SchemaDefinition{PrimaryKeys: []string{"tenant_id", "device_id"}}

	tests := []struct {
		name    string
		schema  *SchemaDefinition
		key     map[string]string
		wantErr string
	}{
		{
			name:   "valid single",
			schema: &SchemaDefinition{PrimaryKeys: []string{"id"}},
			key:    map[string]string{"id": "x"},
		},
		{
			name:   "valid composite",
			schema: composite,
			key:    map[string]string{"tenant_id": "t", "device_id": "d"},
		},
		{
			name:    "missing column",
			schema:  composite,
			key:     map[string]string{"tenant_id": "t"},
			wantErr: "missing required primary key column",
		},
		{
			name:    "empty value",
			schema:  &SchemaDefinition{PrimaryKeys: []string{"id"}},
			key:     map[string]string{"id": ""},
			wantErr: "must not be empty",
		},
		{
			name:    "unknown extra column",
			schema:  &SchemaDefinition{PrimaryKeys: []string{"id"}},
			key:     map[string]string{"id": "x", "injected": "y"},
			wantErr: "unknown primary key column",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.schema.ValidateEntityKey(tc.key)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}
