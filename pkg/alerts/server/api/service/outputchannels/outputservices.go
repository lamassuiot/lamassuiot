package outputchannels

import (
	"context"

	"github.com/lamassuiot/lamassuiot/pkg/alerts/common/api"
)

type OutputChannels interface {
	ParseEventAndSend(ctx context.Context, eventType string, eventDescription string, eventData map[string]string, channels []api.Channel) error
}
