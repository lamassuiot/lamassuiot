package config

import "github.com/lamassuiot/lamassuiot/pkg/v3/models"

type CAConfig struct {
	BaseConfig `mapstructure:",squash"`
	Storage    PluggableStorageEngine `mapstructure:"storage"`

	CryptoEngine models.CryptoEngineType `mapstructure:"crypto_engine"`

	PKCS11Provider struct {
		Name     string                 `mapstructure:"name"`
		Metadata map[string]interface{} `mapstructure:"metadata"`
		Token    string                 `mapstructure:"token"`
	} `mapstructure:"pkcs11"`
	HashicorpVaultProvider HashicorpVaultCryptoEngineConfig `mapstructure:"hashicrorp_vault"`
	AWSKMSProvider         struct {
		Name            string                 `mapstructure:"name"`
		Metadata        map[string]interface{} `mapstructure:"metadata"`
		AccessKeyID     string                 `mapstructure:"access_key_id"`
		SecretAccessKey string                 `mapstructure:"secret_access_key"`
		Region          string                 `mapstructure:"region"`
	} `mapstructure:"aws_kms"`
	AWSSecretsManagerProvider struct {
		Name            string                 `mapstructure:"name"`
		Metadata        map[string]interface{} `mapstructure:"metadata"`
		AccessKeyID     string                 `mapstructure:"access_key_id"`
		SecretAccessKey string                 `mapstructure:"secret_access_key"`
		Region          string                 `mapstructure:"region"`
	} `mapstructure:"aws_secrets_manager"`
	GoPemProvider struct {
		Name             string                 `mapstructure:"name"`
		Metadata         map[string]interface{} `mapstructure:"metadata"`
		StorageDirectory string                 `mapstructure:"storage_directory"`
	} `mapstructure:"gopem"`

	CryptoMonitoring `mapstructure:"crypto_monitoring"`
	OCSPServerURL    string `mapstructure:"ocsp_server_url"`
}

type HashicorpVaultCryptoEngineConfig struct {
	Name               string                 `mapstructure:"name"`
	Metadata           map[string]interface{} `mapstructure:"metadata"`
	RoleID             string                 `mapstructure:"role_id"`
	SecretID           string                 `mapstructure:"secret_id"`
	AutoUnsealEnabled  bool                   `mapstructure:"auto_unseal_enabled"`
	AutoUnsealKeysFile string                 `mapstructure:"auto_unseal_keys_file"`
	MountPath          string                 `mapstructure:"mount_path"`
	HTTPConnection     `mapstructure:",squash"`
}

type CryptoMonitoring struct {
	Enabled             bool   `mapstructure:"enabled"`
	Frequency           string `mapstructure:"frequency"`
	StatusMachineDeltas struct {
		NearExpiration     string `mapstructure:"near_expiration"`
		CriticalExpiration string `mapstructure:"critical_expiration"`
	} `mapstructure:"status_machine_deltas"`
	AutomaticCARotation struct {
		Enabled      bool   `mapstructure:"enabled"`
		RenewalDelta string `mapstructure:"renewal_delta"`
	} `mapstructure:"automatic_ca_rotation"`
}
