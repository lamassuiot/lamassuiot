package auditpub

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

// Binding writes decide whether a key may be deleted, so every attempt is audited, including the ones
// that change nothing or fail.
func TestKMSBindingWritesAreAudited(t *testing.T) {
	resource := models.KMSBindResource{ResourceType: models.KMSBindResourceTypeCertificate, ResourceID: "aa"}
	bindingInput := services.KeyResourceBindingInput{Identifier: "pkcs11:token-id=e;id=k;type=private", Resource: resource}
	failure := errors.New("storage down")

	call := map[string]func(services.KMSService) (bool, error){
		"BindKeyResource": func(svc services.KMSService) (bool, error) {
			return svc.BindKeyResource(context.Background(), bindingInput)
		},
		"UnbindKeyResource": func(svc services.KMSService) (bool, error) {
			return svc.UnbindKeyResource(context.Background(), bindingInput)
		},
	}
	inputOf := map[string]any{"BindKeyResource": bindingInput, "UnbindKeyResource": bindingInput}

	for method := range call {
		for _, tc := range []struct {
			name      string
			changed   bool
			err       error
			wantType  string
			wantError bool
		}{
			{name: "changed", changed: true, wantType: "audit.kms.bindings.update"},
			{name: "unchanged", changed: false, wantType: "audit.kms.bindings.update"},
			{name: "failed", err: failure, wantType: "kms.bindings.update.error", wantError: true},
		} {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				next := new(svcmock.MockKMSService)
				next.On(method, mock.Anything, mock.Anything).Return(tc.changed, tc.err)
				pub := new(CloudEventPublisherMock)
				pub.On("PublishCloudEvent", mock.Anything, mock.Anything).Return()

				changed, err := call[method](NewKMSAuditEventBusPublisher(AuditPublisher{ICloudEventPublisher: pub})(next))
				require.ErrorIs(t, err, tc.err)
				require.Equal(t, tc.changed, changed, "auditing must not alter the result")

				require.Len(t, pub.Calls, 1, "one audit record per call")
				ctx := pub.Calls[0].Arguments.Get(0).(context.Context)
				require.Equal(t, tc.wantType, ctx.Value(lamassucore.LamassuContextKeyEventType))
				body := pub.Calls[0].Arguments.Get(1).(AuditBody)
				require.Equal(t, inputOf[method], body.Input)
				require.Equal(t, tc.wantError, body.HasError)
				if !tc.wantError {
					require.Equal(t, tc.changed, body.Output)
				}
			})
		}
	}
}
