package api

// -------------------------------------------------------------
type AddUserConfigOutputSerialized struct {
	UserID           string   `json:"user_id"`
	Email            string   `json:"email"`
	SubscribedEvents []string `json:"events"`
}

func (o *AddUserConfigOutput) Serialize() AddUserConfigOutputSerialized {
	return AddUserConfigOutputSerialized{
		UserID:           o.UserID,
		Email:            o.Email,
		SubscribedEvents: o.SubscribedEvents,
	}
}

func (o *AddUserConfigOutputSerialized) Deserialize() AddUserConfigOutput {

	serializer := AddUserConfigOutput{
		UserConfiguration: UserConfiguration{
			UserID:           o.UserID,
			Email:            o.Email,
			SubscribedEvents: o.SubscribedEvents,
		},
	}
	return serializer
}

// -------------------------------------------------------------
type SubscribedEventOutputSerialized struct {
	UserID           string   `json:"user_id"`
	Email            string   `json:"email"`
	SubscribedEvents []string `json:"events"`
}

func (o *SubscribedEventOutput) Serialize() SubscribedEventOutputSerialized {
	return SubscribedEventOutputSerialized{
		UserID:           o.UserID,
		Email:            o.Email,
		SubscribedEvents: o.SubscribedEvents,
	}
}

func (o *SubscribedEventOutputSerialized) Deserialize() SubscribedEventOutput {

	serializer := SubscribedEventOutput{
		UserConfiguration: UserConfiguration{
			UserID:           o.UserID,
			Email:            o.Email,
			SubscribedEvents: o.SubscribedEvents,
		},
	}
	return serializer
}

// -------------------------------------------------------------
type UnsubscribedEventOutputSerialized struct {
	UserID           string   `json:"user_id"`
	Email            string   `json:"email"`
	SubscribedEvents []string `json:"events"`
}

func (o *UnsubscribedEventOutput) Serialize() UnsubscribedEventOutputSerialized {
	return UnsubscribedEventOutputSerialized{
		UserID:           o.UserID,
		Email:            o.Email,
		SubscribedEvents: o.SubscribedEvents,
	}
}

func (o *UnsubscribedEventOutputSerialized) Deserialize() UnsubscribedEventOutput {

	serializer := UnsubscribedEventOutput{
		UserConfiguration: UserConfiguration{
			UserID:           o.UserID,
			Email:            o.Email,
			SubscribedEvents: o.SubscribedEvents,
		},
	}
	return serializer
}
