package config

import (
	"reflect"
	"testing"
)

type TestConfig struct {
	Key string
}

func TestCryptoEngineConfigAdapterMarshal(t *testing.T) {
	ce := CryptoEngineConfig{
		ID:       "test-id",
		Metadata: map[string]interface{}{"meta": "data"},
		Type:     HashicorpVaultProvider,
		Config:   map[string]interface{}{"Key": "value"},
	}

	adapter := CryptoEngineConfigAdapter[TestConfig]{}
	result, err := adapter.Marshal(ce)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	expectedConfig := TestConfig{Key: "value"}
	if result.ID != ce.ID || !reflect.DeepEqual(result.Metadata, ce.Metadata) || result.Type != ce.Type || !reflect.DeepEqual(result.Config, expectedConfig) {
		t.Errorf("expected %v, got %v", ce, result)
	}
}

func TestCryptoEngineConfigAdapterUnmarshal(t *testing.T) {
	adapter := CryptoEngineConfigAdapter[TestConfig]{
		ID:       "test-id",
		Metadata: map[string]interface{}{"meta": "data"},
		Type:     HashicorpVaultProvider,
		Config:   TestConfig{Key: "value"},
	}

	result, err := adapter.Unmarshal()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	expectedConfig := map[string]interface{}{"Key": "value"}
	if result.ID != adapter.ID || !reflect.DeepEqual(result.Metadata, adapter.Metadata) || result.Type != adapter.Type || !reflect.DeepEqual(result.Config, expectedConfig) {
		t.Errorf("expected %v, got %v", adapter, result)
	}
}
