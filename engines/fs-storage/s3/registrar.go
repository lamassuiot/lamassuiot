package s3

import (
	"context"

	s3v2 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	fsstorage "github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/fs-storage"
	sharedAWS "github.com/lamassuiot/lamassuiot/shared/aws/v3"
	log "github.com/sirupsen/logrus"
	"gocloud.dev/blob"
	"gocloud.dev/blob/s3blob"
)

func Register() {
	fsstorage.RegisterFSStorageEngine(config.AWSS3, func(logger *log.Entry, conf config.FSStorageConfig) (*blob.Bucket, error) {
		engineConfig, _ := config.FSStorageConfigAdapter[AWSS3FilesystemConfig]{}.Marshal(conf)

		awsCfg, err := sharedAWS.GetAwsSdkConfig(engineConfig.Config.AWSSDKConfig)
		if err != nil {
			return nil, err
		}

		clientV2 := s3v2.NewFromConfig(*awsCfg)
		bucket, err := s3blob.OpenBucketV2(context.Background(), clientV2, engineConfig.Config.BucketName, nil)

		if err != nil {
			return nil, err
		}

		return bucket, nil
	})
}
