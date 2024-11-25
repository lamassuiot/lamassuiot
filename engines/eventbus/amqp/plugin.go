package main

import (
	"github.com/lamassuiot/lamassuiot/v3/engines/eventbus/amqp/amqp"
	ampq_subsystem "github.com/lamassuiot/lamassuiot/v3/engines/eventbus/amqp/subsystem"
)

func init() {
	amqp.Register()
	ampq_subsystem.Register()
}
