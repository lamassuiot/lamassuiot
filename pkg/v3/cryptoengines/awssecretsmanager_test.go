package cryptoengines

import (
	"testing"

	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/sirupsen/logrus"
)

func TestSetup(t *testing.T) {
	cfg := config.AWSSDKConfig(config.AWSSDKConfig{
		AccessKeyID:     "test",
		SecretAccessKey: "test",
		Region:          "us-east-1",
	})

	sm, err := NewAWSSecretManagerEngine(logrus.WithField("", ""), config.GetAwsSdkConfig(cfg), map[string]any{})
	chk(err)

	_, err = sm.CreateRSAPrivateKey(2048, "123")
	chk(err)
}

func chk(err error) {
	if err != nil {
		panic(err)
	}
}
