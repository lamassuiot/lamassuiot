package helpers

import (
	"testing"
)

func TestGetMetadataToStruct(t *testing.T) {
	metadata := map[string]any{
		"key1": "value1",
		"key2": 123,
		"key3": true,
	}

	var str string
	ok, err := GetMetadataToStruct(metadata, "key1", &str)
	if !ok || err != nil {
		t.Errorf("GetMetadataToStruct failed for key1")
	}

	var num int
	ok, err = GetMetadataToStruct(metadata, "key2", &num)
	if !ok || err != nil {
		t.Errorf("GetMetadataToStruct failed for key2")
	}

	var flag bool
	ok, err = GetMetadataToStruct(metadata, "key3", &flag)
	if !ok || err != nil {
		t.Errorf("GetMetadataToStruct failed for key3")
	}

	ok, err = GetMetadataToStruct(metadata, "key4", &str)
	if ok || err != nil {
		t.Errorf("GetMetadataToStruct should have returned false for key4")
	}
}

func TestGetMetadataToStruct_NonexistentKey(t *testing.T) {
	metadata := map[string]any{
		"key1": "value1",
		"key2": 123,
		"key3": true,
	}

	var str string
	ok, err := GetMetadataToStruct(metadata, "key5", &str)
	if ok || err != nil {
		t.Errorf("GetMetadataToStruct should have returned false for key5")
	}
}
