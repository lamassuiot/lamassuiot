package api

// ---------------------------------------------------------------------

type AddUserConfigPayload struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
}

// ---------------------------------------------------------------------

type SubscribedEventPayload struct {
	UserID    string   `json:"user_id"`
	EventType []string `json:"event_type"`
}

// ---------------------------------------------------------------------

type UnsubscribedEventPayload struct {
	UserID    string   `json:"user_id"`
	EventType []string `json:"event_type"`
}
