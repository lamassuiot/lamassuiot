package helpers

import (
	"reflect"
	"testing"
)

func TestMergeMaps(t *testing.T) {

	var m1, m2 *map[string]int
	expected1 := map[string]int{}
	result1 := MergeMaps(m1, m2)
	if !reflect.DeepEqual(*result1, expected1) {
		t.Errorf("Expected %v, but got %v", expected1, *result1)
	}

	m1 = nil
	m2 = &map[string]int{"a": 1, "b": 2}
	expected2 := map[string]int{"a": 1, "b": 2}
	result2 := MergeMaps(m1, m2)
	if !reflect.DeepEqual(*result2, expected2) {
		t.Errorf("Expected %v, but got %v", expected2, *result2)
	}

	m1 = &map[string]int{"x": 10, "y": 20}
	m2 = nil
	expected3 := map[string]int{"x": 10, "y": 20}
	result3 := MergeMaps(m1, m2)
	if !reflect.DeepEqual(*result3, expected3) {
		t.Errorf("Expected %v, but got %v", expected3, *result3)
	}

	m1 = &map[string]int{"x": 10, "y": 20}
	m2 = &map[string]int{"a": 1, "b": 2}
	expected4 := map[string]int{"x": 10, "y": 20, "a": 1, "b": 2}
	result4 := MergeMaps(m1, m2)
	if !reflect.DeepEqual(*result4, expected4) {
		t.Errorf("Expected %v, but got %v", expected4, *result4)
	}

	m1 = &map[string]int{"x": 10, "y": 20}
	m2 = &map[string]int{"x": 30, "y": 40}
	expected5 := map[string]int{"x": 30, "y": 40}
	result5 := MergeMaps(m1, m2)
	if !reflect.DeepEqual(*result5, expected5) {
		t.Errorf("Expected %v, but got %v", expected5, *result5)
	}
}
