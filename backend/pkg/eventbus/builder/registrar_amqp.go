//go:build !noamqp

package builder

import (
	"github.com/lamassuiot/lamassuiot/v4/engines/eventbus/amqp"
	ampq_subsystem "github.com/lamassuiot/lamassuiot/v4/engines/eventbus/amqp/subsystem"
)

func init() {
	amqp.Register()
	ampq_subsystem.Register()
}
