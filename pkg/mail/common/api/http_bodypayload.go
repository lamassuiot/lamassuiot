package api

// ---------------------------------------------------------------------

type SubscribedEventPayload struct {
	Email     string `json:"email"`
	EventType string `json:"event_type"`
}

// ---------------------------------------------------------------------

type UnsubscribedEventPayload struct {
	Email     string `json:"email"`
	EventType string `json:"event_type"`
}

// ---------------------------------------------------------------------

type GetEventsPayload struct {
	Email     string `json:"email"`
	EventType string `json:"event_type"`
}
