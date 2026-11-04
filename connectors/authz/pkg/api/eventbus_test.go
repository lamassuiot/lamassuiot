//go:build !noamqp && !noaws

package api

import (
	"testing"

	coreeventbus "github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/eventbus"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestAuthzRegistersEventBusProviders(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())

	amqpEngine, err := coreeventbus.GetEventBusEngine("amqp", nil, "authz", logger)
	require.NoError(t, err)
	require.NotNil(t, amqpEngine)

	awsEngine, err := coreeventbus.GetEventBusEngine("aws_sqs_sns", nil, "authz", logger)
	require.NoError(t, err)
	require.NotNil(t, awsEngine)
}
