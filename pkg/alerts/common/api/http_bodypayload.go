package api

// ---------------------------------------------------------------------

type SubscribedEventPayload struct {
	UserID     string                 `json:"user_id"`
	EventType  string                 `json:"event_type"`
	Channel    ChannelCreationPayload `json:"channel"`
	Conditions []string               `json:"conditions"`
}

type ChannelCreationPayload struct {
	Type   ChannelType `json:"type"`
	Name   string      `json:"name"`
	Config interface{} `json:"config"`
}

// ---------------------------------------------------------------------

type UnsubscribedEventPayload struct {
	UserID         string `json:"user_id"`
	SubscriptionID string `json:"subscription_id"`
}

// ---------------------------------------------------------------------
