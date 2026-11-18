//go:build !noaws

package builder

import "github.com/lamassuiot/lamassuiot/v4/engines/eventbus/aws"

func init() {
	aws.Register()
}
