package controllers

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
)

func TestFilterQuery_SubjectKeyID(t *testing.T) {
	req := &http.Request{}
	req.URL = &url.URL{}
	q := req.URL.Query()
	q.Add("filter", "subject_key_id[eq]ABC123")
	req.URL.RawQuery = q.Encode()

	qp := FilterQuery(req, resources.CertificateFilterableFields)
	if qp == nil {
		t.Fatalf("expected QueryParameters, got nil")
	}

	if len(qp.Filters) != 1 {
		t.Fatalf("expected 1 filter, got %d", len(qp.Filters))
	}

	f := qp.Filters[0]
	if f.Field != "subject_key_id" {
		t.Fatalf("expected field 'subject_key_id', got '%s'", f.Field)
	}
	if f.Value != "ABC123" {
		t.Fatalf("expected value 'ABC123', got '%s'", f.Value)
	}
	if f.FilterOperation != resources.StringEqual {
		t.Fatalf("expected operation StringEqual, got %v", f.FilterOperation)
	}
}

func TestFilterQuery_DMSCreationDate(t *testing.T) {
	req := &http.Request{}
	req.URL = &url.URL{}
	q := req.URL.Query()
	q.Add("filter", "creation_date[after]2024-01-01T00:00:00Z")
	req.URL.RawQuery = q.Encode()

	qp := FilterQuery(req, resources.DMSFilterableFields)
	if qp == nil {
		t.Fatalf("expected QueryParameters, got nil")
	}

	if len(qp.Filters) != 1 {
		t.Fatalf("expected 1 filter, got %d", len(qp.Filters))
	}

	f := qp.Filters[0]
	if f.Field != "creation_date" {
		t.Fatalf("expected field 'creation_date', got '%s'", f.Field)
	}
	if f.Value != "2024-01-01T00:00:00Z" {
		t.Fatalf("expected value '2024-01-01T00:00:00Z', got '%s'", f.Value)
	}
	if f.FilterOperation != resources.DateAfter {
		t.Fatalf("expected operation DateAfter, got %v", f.FilterOperation)
	}
}

func TestFilterQuery_JsonFilter_SimpleJsonPath(t *testing.T) {
	req := &http.Request{}
	req.URL = &url.URL{}
	q := req.URL.Query()
	q.Add("filter", "metadata[jsonpath]$.environment")
	req.URL.RawQuery = q.Encode()

	qp := FilterQuery(req, resources.KMSFilterableFields)
	if qp == nil {
		t.Fatalf("expected QueryParameters, got nil")
	}

	if len(qp.Filters) != 1 {
		t.Fatalf("expected 1 filter, got %d", len(qp.Filters))
	}

	f := qp.Filters[0]
	if f.Field != "metadata" {
		t.Fatalf("expected field 'metadata', got '%s'", f.Field)
	}
	if f.Value != "$.environment" {
		t.Fatalf("expected value '$.environment', got '%s'", f.Value)
	}
	if f.FilterOperation != resources.JsonPathExpression {
		t.Fatalf("expected operation JsonPathExpression, got %v", f.FilterOperation)
	}
}

func TestFilterQuery_JsonFilter_ComplexJsonPathWithURLEncoding(t *testing.T) {
	req := &http.Request{}
	req.URL = &url.URL{}
	q := req.URL.Query()
	// JSONPath expression: $.tags[?(@.key == "production")]
	// URL-encoded: %24.tags%5B%3F%28%40.key%20%3D%3D%20%22production%22%29%5D
	q.Add("filter", "metadata[jsonpath]%24.tags%5B%3F%28%40.key%20%3D%3D%20%22production%22%29%5D")
	req.URL.RawQuery = q.Encode()

	qp := FilterQuery(req, resources.KMSFilterableFields)
	if qp == nil {
		t.Fatalf("expected QueryParameters, got nil")
	}

	if len(qp.Filters) != 1 {
		t.Fatalf("expected 1 filter, got %d", len(qp.Filters))
	}

	f := qp.Filters[0]
	if f.Field != "metadata" {
		t.Fatalf("expected field 'metadata', got '%s'", f.Field)
	}
	expectedValue := `$.tags[?(@.key == "production")]`
	if f.Value != expectedValue {
		t.Fatalf("expected value '%s', got '%s'", expectedValue, f.Value)
	}
	if f.FilterOperation != resources.JsonPathExpression {
		t.Fatalf("expected operation JsonPathExpression, got %v", f.FilterOperation)
	}
}

func TestFilterQuery_JsonFilter_InvalidOperand(t *testing.T) {
	req := &http.Request{}
	req.URL = &url.URL{}
	q := req.URL.Query()
	// Use an invalid operand (not "jsonpath")
	q.Add("filter", "metadata[eq]somevalue")
	req.URL.RawQuery = q.Encode()

	qp := FilterQuery(req, resources.KMSFilterableFields)
	if qp == nil {
		t.Fatalf("expected QueryParameters, got nil")
	}

	// Filter is added even with invalid operand, but with UnspecifiedFilter operation
	if len(qp.Filters) != 1 {
		t.Fatalf("expected 1 filter, got %d", len(qp.Filters))
	}

	f := qp.Filters[0]
	if f.Field != "metadata" {
		t.Fatalf("expected field 'metadata', got '%s'", f.Field)
	}
	if f.Value != "somevalue" {
		t.Fatalf("expected value 'somevalue', got '%s'", f.Value)
	}
	if f.FilterOperation != resources.UnspecifiedFilter {
		t.Fatalf("expected operation UnspecifiedFilter (0), got %v", f.FilterOperation)
	}
}

func TestFilterQuery_JsonFilter_MultipleJsonPaths(t *testing.T) {
	req := &http.Request{}
	req.URL = &url.URL{}
	q := req.URL.Query()
	q.Add("filter", "metadata[jsonpath]$.environment")
	q.Add("filter", "metadata[jsonpath]$.region")
	req.URL.RawQuery = q.Encode()

	qp := FilterQuery(req, resources.KMSFilterableFields)
	if qp == nil {
		t.Fatalf("expected QueryParameters, got nil")
	}

	if len(qp.Filters) != 2 {
		t.Fatalf("expected 2 filters, got %d", len(qp.Filters))
	}

	// Check first filter
	f1 := qp.Filters[0]
	if f1.Field != "metadata" {
		t.Fatalf("expected field 'metadata', got '%s'", f1.Field)
	}
	if f1.Value != "$.environment" {
		t.Fatalf("expected value '$.environment', got '%s'", f1.Value)
	}
	if f1.FilterOperation != resources.JsonPathExpression {
		t.Fatalf("expected operation JsonPathExpression, got %v", f1.FilterOperation)
	}

	// Check second filter
	f2 := qp.Filters[1]
	if f2.Field != "metadata" {
		t.Fatalf("expected field 'metadata', got '%s'", f2.Field)
	}
	if f2.Value != "$.region" {
		t.Fatalf("expected value '$.region', got '%s'", f2.Value)
	}
	if f2.FilterOperation != resources.JsonPathExpression {
		t.Fatalf("expected operation JsonPathExpression, got %v", f2.FilterOperation)
	}
}

func TestFilterQuery_JsonPathSort(t *testing.T) {
	req := &http.Request{}
	req.URL = &url.URL{}
	q := req.URL.Query()
	q.Add("sort_by", "metadata[jsonpath]$.env")
	req.URL.RawQuery = q.Encode()

	filterFieldMap := map[string]resources.FilterFieldType{
		"metadata": resources.JsonFilterFieldType,
	}

	qp := FilterQuery(req, filterFieldMap)
	if qp == nil {
		t.Fatalf("expected QueryParameters, got nil")
	}

	if qp.Sort.SortField != "metadata" {
		t.Errorf("expected sort field 'metadata', got '%s'", qp.Sort.SortField)
	}
	if qp.Sort.JsonPathExpr != "$.env" {
		t.Errorf("expected json path '$.env', got '%s'", qp.Sort.JsonPathExpr)
	}
}
func TestIsValidJsonPath(t *testing.T) {
	tests := []struct {
		name     string
		jsonPath string
		valid    bool
	}{
		// Valid paths
		{"simple property", "$.environment", true},
		{"nested property", "$.location.region", true},
		{"with numbers", "$.config123.value456", true},
		{"with underscores", "$.my_field.sub_field", true},
		{"deep nesting", "$.a.b.c.d.e.f", true},

		// Invalid paths - SQL injection attempts
		{"single quote", "$.field'; DROP TABLE devices; --", false},
		{"double quote", `$.field"; DROP TABLE devices; --`, false},
		{"semicolon", "$.field;DELETE FROM devices", false},
		{"comment", "$.field--", false},
		{"union attack", "$.field' UNION SELECT * FROM users--", false},
		{"parentheses", "$.field()", false},
		{"brackets", "$.field[]", false},
		{"spaces", "$.field name", false},
		{"hyphen", "$.field-name", false},
		{"asterisk", "$.field*", false},
		{"backslash", "$.field\\escape", false},

		// Invalid structure
		{"no prefix", "environment", false},
		{"double dots", "$.field..nested", false},
		{"trailing dot", "$.field.", false},
		{"leading dot after prefix", "$..field", false},
		{"empty", "", false},
		{"too long", "$." + string(make([]byte, 250)), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidJsonPath(tt.jsonPath)
			if result != tt.valid {
				t.Errorf("isValidJsonPath(%q) = %v, want %v", tt.jsonPath, result, tt.valid)
			}
		})
	}
}

func TestFilterQuery_JsonPathSort_SQLInjection(t *testing.T) {
	// Test that SQL injection attempts are rejected
	maliciousInputs := []string{
		"metadata[jsonpath]$.field'; DROP TABLE devices; --",
		"metadata[jsonpath]$.field\"; DELETE FROM devices; --",
		"metadata[jsonpath]$.field' UNION SELECT * FROM users--",
		"metadata[jsonpath]$.field(); ",
	}

	filterFieldMap := map[string]resources.FilterFieldType{
		"metadata": resources.JsonFilterFieldType,
	}

	for _, input := range maliciousInputs {
		req := &http.Request{}
		req.URL = &url.URL{}
		q := req.URL.Query()
		q.Add("sort_by", input)
		req.URL.RawQuery = q.Encode()

		qp := FilterQuery(req, filterFieldMap)
		if qp.Sort.JsonPathExpr != "" {
			t.Errorf("SQL injection attempt should be rejected: %s", input)
			t.Errorf("Got JsonPathExpr: %s", qp.Sort.JsonPathExpr)
		}
	}
}
