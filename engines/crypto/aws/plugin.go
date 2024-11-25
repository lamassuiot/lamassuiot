package main

import (
	"github.com/lamassuiot/lamassuiot/v3/engines/crypto/aws/aws"
	"github.com/lamassuiot/lamassuiot/v3/engines/crypto/aws/subsystem"
)

func init() {
	aws.RegisterAWSKMS()
	aws.RegisterAWSSecrets()
	subsystem.Register()
}
