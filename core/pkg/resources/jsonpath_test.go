package resources

import (
	"reflect"
	"testing"
)

func TestParseSortJsonPath(t *testing.T) {
	tests := []struct {
		path string
		want []string
	}{
		{"$.environment", []string{"environment"}},
		{"$.location.region", []string{"location", "region"}},
		{"$.my_field.sub-field", []string{"my_field", "sub-field"}},
		{"$.tags[0]", []string{"tags", "0"}},
		{"$.tags[1]", []string{"tags", "1"}},
		{"$.tags[last]", []string{"tags", "-1"}},
		{"$.a[0].b", []string{"a", "0", "b"}},
		{"$.a[0][1]", []string{"a", "0", "1"}},
		{"$[0]", []string{"0"}},
		{"$[last].name", []string{"-1", "name"}},
	}
	for _, tt := range tests {
		got, err := ParseSortJsonPath(tt.path)
		if err != nil {
			t.Errorf("ParseSortJsonPath(%q) unexpected error: %v", tt.path, err)
			continue
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("ParseSortJsonPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestParseSortJsonPath_Rejects(t *testing.T) {
	paths := []string{
		"",
		"$",
		"environment",
		"$.",
		"$.a.",
		"$.a..b",
		"$..a",
		"$a",
		"$.*",
		"$.tags[*]",
		"$.tags[",
		"$.tags[]",
		"$.tags[x]",
		"$.tags[-1]",
		"$.tags[1:2]",
		"$.tags[1 to 3]",
		"$.tags[0]x",
		"$.tags[9999999999]",
		`$["a"]`,
		"$.a b",
		`$.a"b`,
		"$.a'; DROP TABLE x --",
		"$.field ? (@ == 1)",
		"$.version > 1",
	}
	for _, p := range paths {
		if keys, err := ParseSortJsonPath(p); err == nil {
			t.Errorf("ParseSortJsonPath(%q) = %v, expected error", p, keys)
		}
	}
}
