package main

import (
	"github.com/lamassuiot/lamassuiot/engines/crypto/aws/v3/aws"
	"github.com/lamassuiot/lamassuiot/engines/crypto/aws/v3/subsystem"
)

func init() {
	aws.RegisterAWSKMS()
	aws.RegisterAWSSecrets()
	subsystem.Register()
}
