//go:build !noaws

package builder

import (
	"github.com/lamassuiot/lamassuiot/engines/crypto/aws/v3"
	aws_subsystem "github.com/lamassuiot/lamassuiot/engines/crypto/aws/v3/subsystem"
	log "github.com/sirupsen/logrus"
)

func init() {
	log.Info("Registering  AWS crypto engines")
	aws.RegisterAWSKMS()
	aws.RegisterAWSSecrets()
	aws_subsystem.Register()
}
