//go:build !noaws

package builder

import (
	"github.com/lamassuiot/lamassuiot/v4/engines/crypto/aws"
	aws_subsystem "github.com/lamassuiot/lamassuiot/v4/engines/crypto/aws/subsystem"
)

func init() {
	aws.RegisterAWSKMS()
	aws.RegisterAWSSecrets()
	aws_subsystem.Register()
}
