package eventpub

import (
	coreeventpub "github.com/lamassuiot/lamassuiot/v4/core/pkg/eventpub"
)

type ICloudEventPublisher = coreeventpub.ICloudEventPublisher
type CloudEventPublisher = coreeventpub.CloudEventPublisher
type EventPublisherWithSourceMiddleware = coreeventpub.EventPublisherWithSourceMiddleware

func NewEventPublisherWithSourceMiddleware(publisher ICloudEventPublisher, source string) ICloudEventPublisher {
	return coreeventpub.NewEventPublisherWithSourceMiddleware(publisher, source)
}
