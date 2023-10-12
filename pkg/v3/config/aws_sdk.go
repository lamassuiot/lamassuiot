package config

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

func GetAwsSdkConfig(conf AWSSDKConfig) aws.Config {
	return aws.Config{
		Region:      conf.Region,
		Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(conf.AccessKeyID, string(conf.SecretAccessKey), "")),
	}
}
