package config

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func GetAwsSdkConfig(conf AWSSDKConfig) (*aws.Config, error) {
	customResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		if conf.EndpointURL != "" {
			return aws.Endpoint{
				PartitionID:   "aws",
				URL:           conf.EndpointURL,
				SigningRegion: conf.Region,
			}, nil
		}

		// returning EndpointNotFoundError will allow the service to fallback to its default resolution
		return aws.Endpoint{}, &aws.EndpointNotFoundError{}
	})

	switch conf.AWSAuthenticationMethod {
	case Static:
		creds := aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(conf.AccessKeyID, string(conf.SecretAccessKey), conf.SessionToken))
		creds.Invalidate()
		awsCfg, err := config.LoadDefaultConfig(context.TODO(),
			config.WithRegion(conf.Region),
			config.WithCredentialsProvider(creds),
			config.WithEndpointResolverWithOptions(customResolver),
		)
		if err != nil {
			return nil, fmt.Errorf("cannot load the AWS configs: %s", err)
		}

		return &awsCfg, nil
	case AssumeRole:
		stsCfg, err := config.LoadDefaultConfig(context.TODO(),
			config.WithRegion(conf.Region),
			config.WithEndpointResolverWithOptions(customResolver),
		)
		if err != nil {
			return nil, fmt.Errorf("cannot load the AWS configs: %s", err)
		}
		stsSvc := sts.NewFromConfig(stsCfg)
		creds := aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(stsSvc, conf.RoleARN))
		creds.Invalidate()
		awsCfg, err := config.LoadDefaultConfig(context.TODO(),
			config.WithRegion(conf.Region),
			config.WithCredentialsProvider(creds),
			config.WithEndpointResolverWithOptions(customResolver),
		)
		if err != nil {
			return nil, fmt.Errorf("cannot load the AWS configs: %s", err)
		}
		return &awsCfg, nil
	default:
		return loadAWSDefaultConfig(conf, customResolver)
	}

}

func loadAWSDefaultConfig(conf AWSSDKConfig, customResolver aws.EndpointResolverWithOptionsFunc) (*aws.Config, error) {
	awsCfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(conf.Region),
		config.WithEndpointResolverWithOptions(customResolver),
	)
	if err != nil {
		return nil, fmt.Errorf("cannot load the AWS configs: %s", err)
	}
	return &awsCfg, nil
}
