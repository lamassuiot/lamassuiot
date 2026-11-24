package aws

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func GetAwsSdkConfig(conf AWSSDKConfig) (*aws.Config, error) {
	accessKeyID, secretAccessKey, sessionToken, err := credentialsFromEnvironment(conf)
	if err != nil {
		return nil, err
	}

	customResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...any) (aws.Endpoint, error) {
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
		creds := aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, sessionToken))
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
		stsCfg, err := loadConfigWithOptionalCredentials(conf, accessKeyID, secretAccessKey, sessionToken, customResolver)
		if err != nil {
			return nil, fmt.Errorf("cannot load the AWS configs: %s", err)
		}
		stsSvc := sts.NewFromConfig(*stsCfg)
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
		return loadConfigWithOptionalCredentials(conf, accessKeyID, secretAccessKey, sessionToken, customResolver)
	}

}

func credentialsFromEnvironment(conf AWSSDKConfig) (string, string, string, error) {
	accessKeyID := conf.AccessKeyID
	secretAccessKey := string(conf.SecretAccessKey)
	sessionToken := string(conf.SessionToken)

	for _, binding := range []struct {
		name  string
		value *string
	}{
		{conf.AccessKeyIDEnv, &accessKeyID},
		{conf.SecretAccessKeyEnv, &secretAccessKey},
		{conf.SessionTokenEnv, &sessionToken},
	} {
		if binding.name == "" {
			continue
		}
		value, ok := os.LookupEnv(binding.name)
		if !ok || value == "" {
			return "", "", "", fmt.Errorf("AWS credential environment variable %s is missing or empty", binding.name)
		}
		*binding.value = value
	}

	return accessKeyID, secretAccessKey, sessionToken, nil
}

func loadConfigWithOptionalCredentials(conf AWSSDKConfig, accessKeyID, secretAccessKey, sessionToken string, customResolver aws.EndpointResolverWithOptionsFunc) (*aws.Config, error) {
	options := []func(*config.LoadOptions) error{
		config.WithRegion(conf.Region),
		config.WithEndpointResolverWithOptions(customResolver),
	}
	if conf.AccessKeyIDEnv != "" || conf.SecretAccessKeyEnv != "" || conf.SessionTokenEnv != "" {
		options = append(options, config.WithCredentialsProvider(
			aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, sessionToken)),
		))
	}
	awsCfg, err := config.LoadDefaultConfig(context.TODO(), options...)
	if err != nil {
		return nil, fmt.Errorf("cannot load the AWS configs: %s", err)
	}
	return &awsCfg, nil
}
