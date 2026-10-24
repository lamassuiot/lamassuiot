//go:build !noaws

package builder

import (
	"github.com/lamassuiot/lamassuiot/v4/engines/crypto/aws"
	aws_subsystem "github.com/lamassuiot/lamassuiot/v4/engines/crypto/aws/subsystem"
	log "github.com/sirupsen/logrus"
)

func init() {
	log.Info("Registering AWS crypto engines")
	aws.RegisterAWSKMS()
	aws.RegisterAWSSecrets()
	aws_subsystem.Register()
}
