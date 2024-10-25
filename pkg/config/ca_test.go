package config

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMigrateCryptoEnginesToV2ConfigFromFile(t *testing.T) {

	config1, err := readConfig[CAConfig]("testdata/ca-config.yml", nil)
	if err != nil {
		t.Fatalf("Failed to read config: %v", err)
	}

	config2 := MigrateCryptoEnginesToV2Config(*config1)

	assert.Equal(t, 5, len(config2.CryptoEngines.CryptoEngines), "Expected 5 crypto engines")
	assert.False(t, reflect.DeepEqual(*config1, config2))
}

func TestReadConfigFromFileNoMigrationNeeded(t *testing.T) {

	config, err := readConfig[CAConfig]("testdata/ca-config-v2.yml", nil)
	if err != nil {
		t.Fatalf("Failed to read config: %v", err)
	}

	assert.Equal(t, 5, len(config.CryptoEngines.CryptoEngines), "Expected 5 crypto engines")
}

func TestReadConfigFromFileNoMigrationNeededNoEffect(t *testing.T) {

	config1, err := readConfig[CAConfig]("testdata/ca-config-v2.yml", nil)
	if err != nil {
		t.Fatalf("Failed to read config: %v", err)
	}
	config2 := MigrateCryptoEnginesToV2Config(*config1)

	assert.True(t, reflect.DeepEqual(*config1, config2))
}

func TestMigrateCryptoEnginesToV2Config(t *testing.T) {
	tests := []struct {
		name   string
		config CAConfig
		want   CAConfig
	}{
		{
			name: "NoMigrationNeeded",
			config: CAConfig{
				CryptoEngines: CryptoEngines{
					PKCS11Provider: []PKCS11EngineConfig{{PKCS11Config: PKCS11Config{ModulePath: "dd"}}},
					CryptoEngines: []CryptoEngine{
						{
							ID:       "existing-engine",
							Metadata: map[string]interface{}{},
							Type:     PKCS11Provider,
							Config:   map[string]interface{}{"configKey": "configValue"},
						},
					},
				},
			},
			want: CAConfig{
				CryptoEngines: CryptoEngines{
					PKCS11Provider: []PKCS11EngineConfig{{PKCS11Config: PKCS11Config{ModulePath: "dd"}}},
					CryptoEngines: []CryptoEngine{
						{
							ID:       "existing-engine",
							Metadata: map[string]interface{}{},
							Type:     PKCS11Provider,
							Config:   map[string]interface{}{"configKey": "configValue"},
						},
					},
				},
			},
		},
		{
			name: "MigrateFilesystemProvider",
			config: CAConfig{
				CryptoEngines: CryptoEngines{
					FilesystemProvider: []FilesystemEngineConfig{
						{
							ID:               "filesystem-engine",
							Metadata:         nil,
							StorageDirectory: "/path/to/root",
						},
					},
				},
			},
			want: CAConfig{
				CryptoEngines: CryptoEngines{
					CryptoEngines: []CryptoEngine{
						{
							ID:       "filesystem-engine",
							Metadata: nil,
							Type:     FilesystemProvider,
							Config: map[string]interface{}{
								"storage_directory": "/path/to/root",
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MigrateCryptoEnginesToV2Config(tt.config)
			if !reflect.DeepEqual(got.CryptoEngines.CryptoEngines, tt.want.CryptoEngines.CryptoEngines) {
				t.Errorf("MigrateCryptoEnginesToV2Config() = %v, want %v", got, tt.want)
			}
		})
	}
}
