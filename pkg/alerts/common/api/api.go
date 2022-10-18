package api

import (
	"strings"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
)

type UserSubscription struct {
	Subscriptions []Subscription
}

type Subscription struct {
	ID               string
	UserID           string
	EventType        string
	SubscriptionDate time.Time
	Conditions       []string
	Channel          Channel
	ConditionType    ConditionType
	ExpectedValue    string
}

type ConditionType string

const (
	JSONSchema ConditionType = "json_schema"
	JSONPath   ConditionType = "json_path"
)

func ParseConditionType(s string) ConditionType {
	s = strings.ToLower(s)
	switch s {
	case "json_schema":
		return JSONSchema
	case "json_path":
		return JSONPath
	default:
		return JSONSchema
	}
}

type ChannelType string

const (
	ChannelTypeEmail   ChannelType = "email"
	ChannelTypeMSTeams ChannelType = "msteams"
	ChannelTypeWebhook ChannelType = "webhook"
)

type Channel struct {
	Type   ChannelType
	Name   string
	Config interface{}
}

type LogEvent struct {
	EventType string
	Event     cloudevents.Event
	Date      time.Time
}

// ---------------------------------------------------------------------

type HandleEventInput struct {
	Event cloudevents.Event
}

type HandleEventOutput struct {
}

// ---------------------------------------------------------------------

type ChannelCreation struct {
	Type   ChannelType
	Name   string
	Config interface{}
}

type SubscribeEventInput struct {
	EventType     string
	Conditions    []string
	Channel       ChannelCreation
	UserID        string
	ConditionType ConditionType
}

type SubscribeEventOutput struct {
	UserSubscription
}

// ---------------------------------------------------------------------

type UnsubscribedEventInput struct {
	UserID         string
	SubscriptionID string
}

type UnsubscribedEventOutput struct {
	UserSubscription
}

// ---------------------------------------------------------------------

type GetEventsInput struct {
}

type GetEventsOutput struct {
	LastEvents []cloudevents.Event
}

// ---------------------------------------------------------------------

type GetSubscriptionsInput struct {
	UserID string
}

type GetSubscriptionsOutput struct {
	UserSubscription
}

// ---------------------------------------------------------------------
