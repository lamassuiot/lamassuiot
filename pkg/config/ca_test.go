package config

import (
	"reflect"
	"testing"

	cconfig "github.com/lamassuiot/lamassuiot/v2/core/pkg/config"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestMigrateCryptoEnginesToV2ConfigFromFile(t *testing.T) {

	tlog := logrus.New().WithField("service", "test")

	config1, err := readConfig[CAConfig]("testdata/ca-config.yml", nil)
	if err != nil {
		t.Fatalf("Failed to read config: %v", err)
	}

	config2 := MigrateCryptoEnginesToV2Config(tlog, *config1)

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

	tlog := logrus.New().WithField("service", "test")

	config1, err := readConfig[CAConfig]("testdata/ca-config-v2.yml", nil)
	if err != nil {
		t.Fatalf("Failed to read config: %v", err)
	}
	config2 := MigrateCryptoEnginesToV2Config(tlog, *config1)

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
					PKCS11Provider: []cconfig.PKCS11EngineConfig{{PKCS11Config: cconfig.PKCS11Config{ModulePath: "dd"}}},
					CryptoEngines: []cconfig.CryptoEngine{
						{
							ID:       "existing-engine",
							Metadata: map[string]interface{}{},
							Type:     cconfig.PKCS11Provider,
							Config:   map[string]interface{}{"configKey": "configValue"},
						},
					},
				},
			},
			want: CAConfig{
				CryptoEngines: CryptoEngines{
					PKCS11Provider: []cconfig.PKCS11EngineConfig{{PKCS11Config: cconfig.PKCS11Config{ModulePath: "dd"}}},
					CryptoEngines: []cconfig.CryptoEngine{
						{
							ID:       "existing-engine",
							Metadata: map[string]interface{}{},
							Type:     cconfig.PKCS11Provider,
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
					FilesystemProvider: []cconfig.FilesystemEngineConfig{
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
					CryptoEngines: []cconfig.CryptoEngine{
						{
							ID:       "filesystem-engine",
							Metadata: nil,
							Type:     cconfig.FilesystemProvider,
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
		tlog := logrus.New().WithField("service", "test")
		t.Run(tt.name, func(t *testing.T) {
			got := MigrateCryptoEnginesToV2Config(tlog, tt.config)
			if !reflect.DeepEqual(got.CryptoEngines.CryptoEngines, tt.want.CryptoEngines.CryptoEngines) {
				t.Errorf("MigrateCryptoEnginesToV2Config() = %v, want %v", got, tt.want)
			}
		})
	}
}
