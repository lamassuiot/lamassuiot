//go:build !noaws

package builder

import "github.com/lamassuiot/lamassuiot/pki/v3/engines/eventbus/aws"

func init() {
	aws.Register()
}
