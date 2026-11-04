//go:build !noaws

package api

import "github.com/lamassuiot/lamassuiot/v4/engines/eventbus/aws"

func init() {
	aws.Register()
}
