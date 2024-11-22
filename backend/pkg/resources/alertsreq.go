package resources

import "github.com/lamassuiot/lamassuiot/v3/core/pkg/models"

type SubscribeBody struct {
	EventType  models.EventType               `json:"event_type"`
	Conditions []models.SubscriptionCondition `json:"conditions"`
	Channel    models.Channel                 `json:"channel"`
}
