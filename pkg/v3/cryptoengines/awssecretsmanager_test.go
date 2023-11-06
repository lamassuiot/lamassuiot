package cryptoengines

import (
	"testing"

	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/sirupsen/logrus"
)

func TestSetup(t *testing.T) {
	cfg := config.AWSSDKConfig{
		AccessKeyID:     "test",
		SecretAccessKey: "test",
		Region:          "us-east-1",
		EndpointURL:     "http://127.0.0.1:4566",
	}

	awsCfg, err := config.GetAwsSdkConfig(cfg)
	chk(err)

	sm, err := NewAWSSecretManagerEngine(logrus.WithField("", ""), *awsCfg, map[string]any{})
	chk(err)

	_, err = sm.CreateRSAPrivateKey(2048, "123")
	chk(err)
}

func chk(err error) {
	if err != nil {
		panic(err)
	}
}
