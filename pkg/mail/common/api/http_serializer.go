package api

import cloudevents "github.com/cloudevents/sdk-go/v2"

// -------------------------------------------------------------
type SubscribedEventOutputSerialized struct {
	Email            string   `json:"email"`
	SubscribedEvents []string `json:"events"`
}

func (o *SubscribedEventOutput) Serialize() SubscribedEventOutputSerialized {
	return SubscribedEventOutputSerialized{
		Email:            o.Email,
		SubscribedEvents: o.SubscribedEvents,
	}
}

func (o *SubscribedEventOutputSerialized) Deserialize() SubscribedEventOutput {

	serializer := SubscribedEventOutput{
		Subscription: Subscription{
			Email:            o.Email,
			SubscribedEvents: o.SubscribedEvents,
		},
	}
	return serializer
}

// -------------------------------------------------------------
type UnsubscribedEventOutputSerialized struct {
	Email            string   `json:"email"`
	SubscribedEvents []string `json:"events"`
}

func (o *UnsubscribedEventOutput) Serialize() UnsubscribedEventOutputSerialized {
	return UnsubscribedEventOutputSerialized{
		Email:            o.Email,
		SubscribedEvents: o.SubscribedEvents,
	}
}

func (o *UnsubscribedEventOutputSerialized) Deserialize() UnsubscribedEventOutput {

	serializer := UnsubscribedEventOutput{
		Subscription: Subscription{
			Email:            o.Email,
			SubscribedEvents: o.SubscribedEvents,
		},
	}
	return serializer
}

// -------------------------------------------------------------
type GetEventsOutputSerialized struct {
	EventsLog []cloudevents.Event `json:"last_events"`
}

func (o *GetEventsOutput) Serialize() GetEventsOutputSerialized {
	return GetEventsOutputSerialized{
		EventsLog: o.LastEvents,
	}
}

func (o *GetEventsOutputSerialized) Deserialize() GetEventsOutput {

	serializer := GetEventsOutput{
		LastEvents: o.EventsLog,
	}
	return serializer
}
