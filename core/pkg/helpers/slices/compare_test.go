package lms_slices

import (
	"testing"
)

func TestUnorderedEqualContent(t *testing.T) {
	// Test case 1: Equal slices with string elements
	s1 := []string{"apple", "banana", "cherry"}
	s2 := []string{"banana", "cherry", "apple"}
	cmp := func(e1, e2 string) bool {
		return e1 == e2
	}
	if !UnorderedEqualContent(s1, s2, cmp) {
		t.Errorf("UnorderedEqualContent failed for equal string slices")
	}

	// Test case 2: Equal slices with integer elements
	s3 := []int{1, 2, 3}
	s4 := []int{3, 2, 1}
	cmpInt := func(e1, e2 int) bool {
		return e1 == e2
	}
	if !UnorderedEqualContent(s3, s4, cmpInt) {
		t.Errorf("UnorderedEqualContent failed for equal integer slices")
	}

	// Test case 3: Unequal slices with string elements
	s5 := []string{"apple", "banana", "cherry"}
	s6 := []string{"apple", "banana"}
	if UnorderedEqualContent(s5, s6, cmp) {
		t.Errorf("UnorderedEqualContent should have returned false for unequal string slices")
	}

	// Test case 4: Unequal slices with integer elements
	s7 := []int{1, 2, 3}
	s8 := []int{1, 2}
	if UnorderedEqualContent(s7, s8, cmpInt) {
		t.Errorf("UnorderedEqualContent should have returned false for unequal integer slices")
	}

	// Test case 5: Unequal slices with integer elements, same length
	s9 := []int{1, 2, 3}
	s10 := []int{1, 2, 4}
	if UnorderedEqualContent(s9, s10, cmpInt) {
		t.Errorf("UnorderedEqualContent should have returned false for unequal integer slices")
	}

	// Test case 5: Unequal slices with string elements, same length
	s11 := []string{"apple", "banana", "cherry"}
	s12 := []string{"apple", "banana", "orange"}
	if UnorderedEqualContent(s11, s12, cmp) {
		t.Errorf("UnorderedEqualContent should have returned false for unequal integer slices")
	}
}
