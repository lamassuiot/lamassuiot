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

func TestApplyPatchesNestedArrayInMap(t *testing.T) {
	// Spec1: Add element to non-existing array key (should auto-create array)
	meta1 := map[string]any{
		"existing": "value",
	}

	result1, err := ApplyPatches[map[string]any](
		meta1,
		NewPatchBuilder().
			Add(JSONPointerBuilder("lamassu.io/kms/binded-resources", "0"), map[string]string{
				"resource_type": "certificate",
				"resource_id":   "229bec743f7279e3fd6cb55787442b5c",
			}).
			Build())
	if err != nil {
		t.Fatalf("Spec1: failed to apply patches: %s", err)
	}

	bindedResources, ok := (*result1)["lamassu.io/kms/binded-resources"]
	if !ok {
		t.Fatal("Spec1: missing key lamassu.io/kms/binded-resources")
	}

	bindedResourcesSlice, ok := bindedResources.([]interface{})
	if !ok {
		t.Fatalf("Spec1: expected lamassu.io/kms/binded-resources to be a slice, got %T", bindedResources)
	}

	if len(bindedResourcesSlice) != 1 {
		t.Errorf("Spec1: expected 1 element in array, got %d", len(bindedResourcesSlice))
	}

	firstElement, ok := bindedResourcesSlice[0].(map[string]interface{})
	if !ok {
		t.Fatalf("Spec1: expected first element to be map[string]interface{}, got %T", bindedResourcesSlice[0])
	}

	if firstElement["resource_type"] != "certificate" {
		t.Errorf("Spec1: expected resource_type=certificate, got %v", firstElement["resource_type"])
	}
	if firstElement["resource_id"] != "229bec743f7279e3fd6cb55787442b5c" {
		t.Errorf("Spec1: expected resource_id=229bec743f7279e3fd6cb55787442b5c, got %v", firstElement["resource_id"])
	}

	// Spec2: Append to existing array using "-"
	result2, err := ApplyPatches[map[string]any](
		result1,
		NewPatchBuilder().
			Add(JSONPointerBuilder("lamassu.io/kms/binded-resources", "-"), map[string]string{
				"resource_type": "key",
				"resource_id":   "aabbccdd",
			}).
			Build())
	if err != nil {
		t.Fatalf("Spec2: failed to apply patches: %s", err)
	}

	bindedResources2, ok := (*result2)["lamassu.io/kms/binded-resources"]
	if !ok {
		t.Fatal("Spec2: missing key lamassu.io/kms/binded-resources")
	}

	bindedResourcesSlice2, ok := bindedResources2.([]interface{})
	if !ok {
		t.Fatalf("Spec2: expected lamassu.io/kms/binded-resources to be a slice, got %T", bindedResources2)
	}

	if len(bindedResourcesSlice2) != 2 {
		t.Errorf("Spec2: expected 2 elements in array, got %d", len(bindedResourcesSlice2))
	}

	secondElement, ok := bindedResourcesSlice2[1].(map[string]interface{})
	if !ok {
		t.Fatalf("Spec2: expected second element to be map[string]interface{}, got %T", bindedResourcesSlice2[1])
	}

	if secondElement["resource_type"] != "key" {
		t.Errorf("Spec2: expected resource_type=key, got %v", secondElement["resource_type"])
	}

	// Spec3: Add to empty metadata using "-" (should auto-create array and append)
	meta3 := map[string]any{}

	result3, err := ApplyPatches[map[string]any](
		meta3,
		NewPatchBuilder().
			Add(JSONPointerBuilder("lamassu.io/kms/binded-resources", "-"), map[string]string{
				"resource_type": "certificate",
				"resource_id":   "xyz123",
			}).
			Build())
	if err != nil {
		t.Fatalf("Spec3: failed to apply patches: %s", err)
	}

	bindedResources3, ok := (*result3)["lamassu.io/kms/binded-resources"]
	if !ok {
		t.Fatal("Spec3: missing key lamassu.io/kms/binded-resources")
	}

	bindedResourcesSlice3, ok := bindedResources3.([]interface{})
	if !ok {
		t.Fatalf("Spec3: expected lamassu.io/kms/binded-resources to be a slice, got %T", bindedResources3)
	}

	if len(bindedResourcesSlice3) != 1 {
		t.Errorf("Spec3: expected 1 element in array, got %d", len(bindedResourcesSlice3))
	}
}
