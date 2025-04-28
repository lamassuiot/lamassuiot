package s3

import (
	sharedAWS "github.com/lamassuiot/lamassuiot/shared/aws/v3"
)

type AWSS3FilesystemConfig struct {
	sharedAWS.AWSSDKConfig `mapstructure:",squash"`
	BucketName             string                 `mapstructure:"bucket_name"`
	ID                     string                 `mapstructure:"id"`
	Metadata               map[string]interface{} `mapstructure:"metadata"`
}
