package config

type CAConfig struct {
	BaseConfig `mapstructure:",squash"`
	Storage    PluggableStorageEngine `mapstructure:"storage"`

	CryptoEngines struct {
		PKCS11Providers []struct {
			ID       string                 `mapstructure:"id"`
			Name     string                 `mapstructure:"name"`
			Metadata map[string]interface{} `mapstructure:"metadata"`
			Token    string                 `mapstructure:"token"`
		} `mapstructure:"pkcs11"`
		HashicorpVaultProviders []struct {
			ID                 string                 `mapstructure:"id"`
			Name               string                 `mapstructure:"name"`
			Metadata           map[string]interface{} `mapstructure:"metadata"`
			RoleID             string                 `mapstructure:"role_id"`
			SecretID           string                 `mapstructure:"secret_id"`
			Protocol           HTTPProtocol           `mapstructure:"protocol"`
			BasicConnection    `mapstructure:",squash"`
			AutoUnsealEnabled  bool   `mapstructure:"auto_unseal_enabled"`
			AutoUnsealKeysFile string `mapstructure:"auto_unseal_keys_file"`
		} `mapstructure:"hashicrorp_vault"`
		AWSKMSProviders []struct {
			ID              string                 `mapstructure:"id"`
			Name            string                 `mapstructure:"name"`
			Metadata        map[string]interface{} `mapstructure:"metadata"`
			AccessKeyID     string                 `mapstructure:"access_key_id"`
			SecretAccessKey string                 `mapstructure:"secret_access_key"`
			Region          string                 `mapstructure:"region"`
		} `mapstructure:"aws_kms"`
		GoPemProviders []struct {
			ID               string                 `mapstructure:"id"`
			Name             string                 `mapstructure:"name"`
			Metadata         map[string]interface{} `mapstructure:"metadata"`
			StorageDirectory string                 `mapstructure:"storage_directory"`
		} `mapstructure:"gopem"`
	} `mapstructure:"crypto_engines"`

	CryptoMonitoring `mapstructure:"crypto_monitoring"`
	OCSPServerURL    string `mapstructure:"ocsp_server_url"`
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
