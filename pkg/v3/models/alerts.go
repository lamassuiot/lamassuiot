package models

import (
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
)

type Subscription struct {
	ID               string                  `json:"id" gorm:"primaryKey"`
	UserID           string                  `json:"user_id"`
	EventType        EventType               `json:"event_type"`
	SubscriptionDate time.Time               `json:"subscription_ts"`
	Conditions       []SubscriptionCondition `json:"conditions" gorm:"serializer:json"`
	Channel          Channel                 `json:"channel" gorm:"serializer:json"`
}

type SubscriptionCondition struct {
	Type      ConditionType `json:"type"`
	Condition string        `json:"condition"`
}

type ConditionType string

const (
	JSONSchema ConditionType = "JSON-SCHEMA"
	JSONPath   ConditionType = "JSON-PATH"
)

type ChannelType string

const (
	ChannelTypeEmail   ChannelType = "EMAIL"
	ChannelTypeMSTeams ChannelType = "MSTEAMS"
	ChannelTypeWebhook ChannelType = "WEBHOOK"
)

type Channel struct {
	Type   ChannelType `json:"type"`
	Name   string      `json:"name"`
	Config any         `json:"config" gorm:"serializer:json"`
}

type EmailConfig struct {
	Email string `json:"email"`
}

type MSTeamsChannelConfig struct {
	WebhookURL string `json:"webhook_url"`
}

type WebhookChannelConfig struct {
	WebhookURL    string `json:"webhook_url"`
	WebhookMethod string `json:"webhook_method"`
}

type AlertLatestEvent struct {
	EventType EventType         `json:"event_types" gorm:"primaryKey"`
	Event     cloudevents.Event `json:"event" gorm:"serializer:json"`
	LastSeen  time.Time         `json:"seen_at"`
	TotalSeen int               `json:"counter"`
}
