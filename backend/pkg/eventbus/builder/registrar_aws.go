//go:build !noaws

package builder

import "github.com/lamassuiot/lamassuiot/engines/eventbus/aws/v3"

func init() {
	aws.Register()
}
