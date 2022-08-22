package api

import (
	cloudevents "github.com/cloudevents/sdk-go/v2"
)

type UserConfiguration struct {
	UserID           string
	Email            string
	SubscribedEvents []string
}

// ---------------------------------------------------------------------

type HandleEventInput struct {
	Event cloudevents.Event
}

type HandleEventOutput struct {
}

// ---------------------------------------------------------------------

type AddUserConfigInput struct {
	UserID string
	Email  string
}

type AddUserConfigOutput struct {
	UserConfiguration
}

// ---------------------------------------------------------------------

type SubscribedEventInput struct {
	UserID    string
	EventType []string
}

type SubscribedEventOutput struct {
	UserConfiguration
}

// ---------------------------------------------------------------------

type UnsubscribedEventInput struct {
	UserID    string
	EventType []string
}

type UnsubscribedEventOutput struct {
	UserConfiguration
}
