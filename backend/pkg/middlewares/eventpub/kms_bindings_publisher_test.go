package eventpub

import (
	"context"
	"errors"
	"testing"

	lamassucore "github.com/lamassuiot/lamassuiot/v4/core"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	svcmock "github.com/lamassuiot/lamassuiot/v4/core/pkg/services/mock"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Binding events are only published when the key's bindings actually changed.
func TestKMSBindingEventsOnlyWhenBindingsChange(t *testing.T) {
	resource := models.KMSBindResource{ResourceType: models.KMSBindResourceTypeCertificate, ResourceID: "aa"}
	bindingInput := services.KeyResourceBindingInput{Identifier: "pkcs11:token-id=e;id=k;type=private", Resource: resource}
	rebindInput := services.RebindKeyResourceInput{Identifier: bindingInput.Identifier, From: resource, To: models.KMSBindResource{ResourceType: models.KMSBindResourceTypeCertificate, ResourceID: "bb"}}
	failure := errors.New("storage down")

	call := map[string]func(services.KMSService) error{
		"BindKeyResource": func(svc services.KMSService) error {
			_, err := svc.BindKeyResource(context.Background(), bindingInput)
			return err
		},
		"UnbindKeyResource": func(svc services.KMSService) error {
			_, err := svc.UnbindKeyResource(context.Background(), bindingInput)
			return err
		},
		"RebindKeyResource": func(svc services.KMSService) error {
			return svc.RebindKeyResource(context.Background(), rebindInput)
		},
	}

	for _, tc := range []struct {
		name      string
		method    string
		changed   bool
		err       error
		wantEvent bool
	}{
		{name: "bind that adds a binding", method: "BindKeyResource", changed: true, wantEvent: true},
		{name: "bind of an already bound resource", method: "BindKeyResource", changed: false, wantEvent: false},
		{name: "failed bind", method: "BindKeyResource", err: failure, wantEvent: false},
		{name: "unbind that removes a binding", method: "UnbindKeyResource", changed: true, wantEvent: true},
		{name: "unbind of a resource that was not bound", method: "UnbindKeyResource", changed: false, wantEvent: false},
		{name: "rebind", method: "RebindKeyResource", wantEvent: true},
		{name: "failed rebind", method: "RebindKeyResource", err: failure, wantEvent: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := new(svcmock.MockKMSService)
			if tc.method == "RebindKeyResource" {
				next.On(tc.method, mock.Anything, mock.Anything).Return(tc.err)
			} else {
				next.On(tc.method, mock.Anything, mock.Anything).Return(tc.changed, tc.err)
			}
			pub := new(CloudEventPublisherMock)
			pub.On("PublishCloudEvent", mock.Anything, mock.Anything).Return()

			err := call[tc.method](NewKMSEventBusPublisher(pub)(next))
			require.ErrorIs(t, err, tc.err)

			if !tc.wantEvent {
				pub.AssertNotCalled(t, "PublishCloudEvent", mock.Anything, mock.Anything)
				return
			}
			require.Len(t, pub.Calls, 1, "one event per change")
			ctx := pub.Calls[0].Arguments.Get(0).(context.Context)
			require.Equal(t, models.EventUpdateKMSKeyBindings, ctx.Value(lamassucore.LamassuContextKeyEventType))
		})
	}
}
