package helpers

import (
	"reflect"
	"testing"
)

func TestApplyPatchesMap(t *testing.T) {
	meta := map[string]any{
		"test":    "test",
		"lamassu": "lamassu",
		"arr":     []interface{}{"test", "test2"},
	}

	checkValue := func(t *testing.T, spec string, result map[string]any, key string, expected any) {
		t.Helper()
		val, ok := result[key]
		if !ok {
			t.Errorf("%s: missing key %s", spec, key)
			return
		}
		if !reflect.DeepEqual(val, expected) {
			t.Errorf("%s: expected %v, got %v", spec, expected, val)
		}
	}

	// Spec1: Update existing key "test"
	result1, err := ApplyPatches[map[string]any](
		meta,
		NewPatchBuilder().
			Add(JSONPointerBuilder("test"), "newVal").
			Build())
	if err != nil {
		t.Fatalf("Spec1: failed to apply patches: %s", err)
	}
	checkValue(t, "Spec1", *result1, "test", "newVal")

	// Spec2: Add nested key "NOTEXISTINGKEY2/MULTIPLELEVELS"
	result2, err := ApplyPatches[map[string]any](
		result1,
		NewPatchBuilder().
			Add(JSONPointerBuilder("NOTEXISTINGKEY2", "MULTIPLELEVELS"), "newVal").
			Build())
	if err != nil {
		t.Fatalf("Spec2: failed to apply patches: %s", err)
	}

	nVal, ok := (*result2)["NOTEXISTINGKEY2"]
	if !ok {
		t.Fatal("Spec2: missing key NOTEXISTINGKEY2")
	}
	nValMap, ok := nVal.(map[string]any)
	if !ok {
		t.Errorf("Spec2: expected NOTEXISTINGKEY2 to be a map, got %T", nVal)
	} else {
		checkValue(t, "Spec2", nValMap, "MULTIPLELEVELS", "newVal")
	}

	// Spec3: Remove "NOTEXISTINGKEY2"
	result3, err := ApplyPatches[map[string]any](
		result2,
		NewPatchBuilder().
			Remove(JSONPointerBuilder("NOTEXISTINGKEY2")).
			Build())
	if err != nil {
		t.Fatalf("Spec3: failed to apply patches: %s", err)
	}
	if _, ok := (*result3)["NOTEXISTINGKEY2"]; ok {
		t.Errorf("Spec3: NOTEXISTINGKEY2 should be deleted")
	}

	// Spec4: Remove non-existing key (should not fail)
	if _, err := ApplyPatches[map[string]any](
		result3,
		NewPatchBuilder().
			Remove(JSONPointerBuilder("NOTEXISTINGKEY!!")).
			Build(),
	); err != nil {
		t.Errorf("Spec4: failed to apply patches: %s", err)
	}

	// Spec5: Add a key with nil value (should fail)
	if _, err := ApplyPatches[map[string]any](
		result3,
		NewPatchBuilder().
			Add(JSONPointerBuilder("dummy!!"), nil).
			Build(),
	); err == nil {
		t.Fatal("Spec5: adding a nil value should fail")
	}

	// Spec6: Append to array key "arr"
	result6, err := ApplyPatches[map[string]any](
		result3,
		NewPatchBuilder().
			Add(JSONPointerBuilder("arr"), []string{"test3"}).
			Build())
	if err != nil {
		t.Fatalf("Spec6: failed to apply patches: %s", err)
	}

	checkValue(t, "Spec6", *result6, "arr", []interface{}{"test3"})

	// Spec7: Add element with key with "/"
	result7, err := ApplyPatches[map[string]any](
		result3,
		NewPatchBuilder().
			Add(JSONPointerBuilder("key/with/slash"), "test4").
			Build())
	if err != nil {
		t.Fatalf("Spec7: failed to apply patches: %s", err)
	}

	checkValue(t, "Spec7", *result7, "key/with/slash", "test4")
}

func TestApplyPatchesStringSlice(t *testing.T) {
	slice := []string{"one", "two", "three"}

	checkSlice := func(t *testing.T, spec string, result []string, expected []string) {
		t.Helper()
		if !reflect.DeepEqual(result, expected) {
			t.Errorf("%s: expected %v, got %v", spec, expected, result)
		}
	}

	// Spec1: Add an element
	result1, err := ApplyPatches[[]string](
		slice,
		NewPatchBuilder().
			Add(JSONPointerBuilder("1"), "four").
			Build())
	if err != nil {
		t.Fatalf("Spec1: failed to apply patches: %s", err)
	}
	checkSlice(t, "Spec1", *result1, []string{"one", "four", "two", "three"})

	// Spec2: Remove an element
	result2, err := ApplyPatches[[]string](
		*result1,
		NewPatchBuilder().
			Remove(JSONPointerBuilder("0")).
			Build())
	if err != nil {
		t.Fatalf("Spec2: failed to apply patches: %s", err)
	}
	checkSlice(t, "Spec2", *result2, []string{"four", "two", "three"})

	// Spec3: Replace an element
	result3, err := ApplyPatches[[]string](
		*result2,
		NewPatchBuilder().
			Replace(JSONPointerBuilder("2"), "five").
			Build())
	if err != nil {
		t.Fatalf("Spec3: failed to apply patches: %s", err)
	}
	checkSlice(t, "Spec3", *result3, []string{"four", "two", "five"})
}
