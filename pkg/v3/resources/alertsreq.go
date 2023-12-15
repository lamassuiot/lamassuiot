package resources

import "github.com/lamassuiot/lamassuiot/pkg/v3/models"

type SubscribeBody struct {
	EventType  models.EventType               `json:"event_type"`
	Conditions []models.SubscriptionCondition `json:"conditions"`
	Channel    models.Channel                 `json:"channel"`
}
