package api

type UserSubscriptionLogSerialized struct {
	Subscriptions []SubscriptionLogSerialized `json:"subscriptions"`
}

func (o *UserSubscription) ToSerializedLog() UserSubscriptionLogSerialized {
	serializedSubs := make([]SubscriptionLogSerialized, 0)
	for _, sub := range o.Subscriptions {
		serializedSubs = append(serializedSubs, sub.ToSerializedLog())
	}

	return UserSubscriptionLogSerialized{
		Subscriptions: serializedSubs,
	}
}

type SubscriptionLogSerialized struct {
	ID               string            `json:"id"`
	EventType        string            `json:"event_type"`
	SubscriptionDate int               `json:"subscription_date"`
	UserID           string            `json:"user_id"`
	Conditions       []string          `json:"conditions"`
	Channel          ChannelSerialized `json:"channel"`
}

func (o *Subscription) ToSerializedLog() SubscriptionLogSerialized {

	return SubscriptionLogSerialized{
		ID:               o.ID,
		EventType:        o.EventType,
		SubscriptionDate: int(o.SubscriptionDate.UnixMilli()),
		UserID:           o.UserID,
		Conditions:       o.Conditions,
		Channel:          o.Channel.Serialize(),
	}
}

// -------------------------------------------------------------
type SubscribeEventOutputLogSerialized struct {
	UserSubscriptionLogSerialized
}

func (o *SubscribeEventOutput) ToSerializedLog() SubscribeEventOutputLogSerialized {
	serializer := SubscribeEventOutputLogSerialized{
		UserSubscriptionLogSerialized: o.UserSubscription.ToSerializedLog(),
	}
	return serializer
}

// -------------------------------------------------------------
type UnsubscribedEventOutputLogSerialized struct {
	UserSubscriptionLogSerialized
}

func (o *UnsubscribedEventOutput) ToSerializedLog() UnsubscribedEventOutputLogSerialized {
	serializer := UnsubscribedEventOutputLogSerialized{
		UserSubscriptionLogSerialized: o.UserSubscription.ToSerializedLog(),
	}
	return serializer
}

// -------------------------------------------------------------

type GetSubscriptionsOutputLogSerialized struct {
	UserSubscriptionLogSerialized
}

func (o *GetSubscriptionsOutput) ToSerializedLog() GetSubscriptionsOutputLogSerialized {
	serializer := GetSubscriptionsOutputLogSerialized{
		UserSubscriptionLogSerialized: o.UserSubscription.ToSerializedLog(),
	}
	return serializer
}
