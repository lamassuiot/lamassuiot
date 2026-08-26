package azure

import lazure "github.com/lamassuiot/lamassuiot/shared/azure/v3"

type AzureCryptoEngine struct {
	lazure.AzureSDKConfig `mapstructure:",squash"`
	ID                    string                 `mapstructure:"id"`
	Metadata              map[string]interface{} `mapstructure:"metadata"`
}
