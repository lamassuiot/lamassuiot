package resources

import "github.com/lamassuiot/lamassuiot/core/v3/pkg/models"

type SubscribeBody struct {
	EventType  models.EventType               `json:"event_type"`
	Conditions []models.SubscriptionCondition `json:"conditions"`
	Channel    models.Channel                 `json:"channel"`
}
