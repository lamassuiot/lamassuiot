//go:build !noamqp

package builder

import (
	"github.com/lamassuiot/lamassuiot/engines/eventbus/amqp/v3"
	ampq_subsystem "github.com/lamassuiot/lamassuiot/engines/eventbus/amqp/v3/subsystem"
)

func init() {
	amqp.Register()
	ampq_subsystem.Register()
}
