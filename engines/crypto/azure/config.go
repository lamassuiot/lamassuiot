package azure

import lazure "github.com/lamassuiot/lamassuiot/v4/shared/azure"

type AzureCryptoEngine struct {
	lazure.AzureSDKConfig `mapstructure:",squash"`
	ID                    string                 `mapstructure:"id"`
	Metadata              map[string]interface{} `mapstructure:"metadata"`
}
