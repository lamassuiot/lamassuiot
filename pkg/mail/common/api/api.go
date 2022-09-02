package api

import (
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
)

type Subscription struct {
	Email            string
	SubscribedEvents []string
}

type LogEvent struct {
	EventType string
	Event     cloudevents.Event
	Date      time.Time
}
type MailConfigurationSettings struct {
	From                 string
	To                   []string
	Subject              string
	Body                 string
	Host                 string
	Port                 string
	Front                string
	EnableSSL            bool
	EnableTLS            bool
	EnableAuth           bool
	EnableAuthentication bool
	Authentication       Authentication
}
type Authentication struct {
	Username string
	Password string
}

// ---------------------------------------------------------------------

type HandleEventInput struct {
	Event cloudevents.Event
}

type HandleEventOutput struct {
}

// ---------------------------------------------------------------------

type SubscribedEventInput struct {
	Email     string
	EventType string
}

type SubscribedEventOutput struct {
	Subscription
}

// ---------------------------------------------------------------------

type UnsubscribedEventInput struct {
	Email     string
	EventType string
}

type UnsubscribedEventOutput struct {
	Subscription
}

// ---------------------------------------------------------------------

type GetEventsInput struct {
}

type GetEventsOutput struct {
	LastEvents []cloudevents.Event
}

// ---------------------------------------------------------------------

type CheckMailConfigirationInput struct {
	Config MailConfigurationSettings
}

type CheckMailConfigirationOutput struct {
	EmailSent bool
}
