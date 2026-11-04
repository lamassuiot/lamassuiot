//go:build !noamqp

package api

import (
	"github.com/lamassuiot/lamassuiot/v4/engines/eventbus/amqp"
	amqpSubsystem "github.com/lamassuiot/lamassuiot/v4/engines/eventbus/amqp/subsystem"
)

func init() {
	amqp.Register()
	amqpSubsystem.Register()
}
