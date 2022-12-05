package api

type UserSubscriptionSerialized struct {
	Subscriptions []SubscriptionSerialized `json:"subscriptions"`
}

func (o *UserSubscription) Serialize() UserSubscriptionSerialized {
	serializedSubs := make([]SubscriptionSerialized, 0)
	for _, sub := range o.Subscriptions {
		serializedSubs = append(serializedSubs, sub.Serialize())
	}

	return UserSubscriptionSerialized{
		Subscriptions: serializedSubs,
	}
}

type SubscriptionSerialized struct {
	ID               string            `json:"id"`
	EventType        string            `json:"event_type"`
	SubscriptionDate int               `json:"subscription_date"`
	UserID           string            `json:"user_id"`
	Conditions       []string          `json:"conditions"`
	Channel          ChannelSerialized `json:"channel"`
	ConditionType    ConditionType     `json:"condition_type"`
}

func (o *Subscription) Serialize() SubscriptionSerialized {
	return SubscriptionSerialized{
		ID:               o.ID,
		EventType:        o.EventType,
		SubscriptionDate: int(o.SubscriptionDate.UnixMilli()),
		UserID:           o.UserID,
		Conditions:       o.Conditions,
		Channel:          o.Channel.Serialize(),
		ConditionType:    o.ConditionType,
	}
}

type ChannelSerialized struct {
	Type   ChannelType `json:"type"`
	Name   string      `json:"name"`
	Config interface{} `json:"config"`
}

func (o *Channel) Serialize() ChannelSerialized {
	return ChannelSerialized{
		Type:   o.Type,
		Name:   o.Name,
		Config: o.Config,
	}
}

// -------------------------------------------------------------
type UnsubscribedEventOutputSerialized struct {
	UserSubscriptionSerialized
}

func (o *UnsubscribedEventOutput) Serialize() UnsubscribedEventOutputSerialized {
	return UnsubscribedEventOutputSerialized{
		UserSubscriptionSerialized: o.UserSubscription.Serialize(),
	}
}

// -------------------------------------------------------------
type GetSubscriptionsOutputSerialized struct {
	UserSubscriptionSerialized
}

func (o *GetSubscriptionsOutput) Serialize() GetSubscriptionsOutputSerialized {
	return GetSubscriptionsOutputSerialized{
		o.UserSubscription.Serialize(),
	}
}
