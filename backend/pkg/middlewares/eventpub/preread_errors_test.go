package eventpub

import (
	"context"
	"reflect"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	svcmock "github.com/lamassuiot/lamassuiot/v4/core/pkg/services/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type serviceMocker interface {
	On(string, ...interface{}) *mock.Call
}

// The publishers read the resource before updating it, to publish its previous state. The
// controllers map service errors to status codes by identity, so wrapping a "not found" error from
// that read would turn a 404 into a 500.
func TestPublishersReturnPreReadErrorsUnwrapped(t *testing.T) {
	for _, test := range []struct {
		method, preRead string
		notFound        error
		build           func() (any, serviceMocker)
	}{
		{"UpdateCAStatus", "GetCAByID", errs.ErrCANotFound, caPublisher},
		{"UpdateCAProfile", "GetCAByID", errs.ErrCANotFound, caPublisher},
		{"UpdateCAMetadata", "GetCAByID", errs.ErrCANotFound, caPublisher},
		{"ReissueCA", "GetCAByID", errs.ErrCANotFound, caPublisher},
		{"UpdateCertificateStatus", "GetCertificateBySerialNumber", errs.ErrCertificateNotFound, caPublisher},
		{"UpdateCertificateMetadata", "GetCertificateBySerialNumber", errs.ErrCertificateNotFound, caPublisher},
		{"UpdateIssuanceProfile", "GetIssuanceProfileByID", errs.ErrIssuanceProfileNotFound, caPublisher},
		{"UpdateDeviceStatus", "GetDeviceByID", errs.ErrDeviceNotFound, devicePublisher},
		{"UpdateDeviceIdentitySlot", "GetDeviceByID", errs.ErrDeviceNotFound, devicePublisher},
		{"UpdateDeviceMetadata", "GetDeviceByID", errs.ErrDeviceNotFound, devicePublisher},
		{"UpdateDeviceGroup", "GetDeviceGroupByID", errs.ErrDeviceGroupNotFound, devicePublisher},
		{"UpdateDMS", "GetDMSByID", errs.ErrDMSNotFound, dmsPublisher},
		{"UpdateDMSMetadata", "GetDMSByID", errs.ErrDMSNotFound, dmsPublisher},
		{"UpdateKeyMetadata", "GetKey", errs.ErrKeyNotFound, kmsPublisher},
		{"UpdateKeyAliases", "GetKey", errs.ErrKeyNotFound, kmsPublisher},
		{"UpdateKeyName", "GetKey", errs.ErrKeyNotFound, kmsPublisher},
		{"UpdateKeyTags", "GetKey", errs.ErrKeyNotFound, kmsPublisher},
		{"BindKeyResource", "GetKey", errs.ErrKeyNotFound, kmsPublisher},
		{"UnbindKeyResource", "GetKey", errs.ErrKeyNotFound, kmsPublisher},
	} {
		t.Run(test.method, func(t *testing.T) {
			publisher, svc := test.build()

			preRead, ok := reflect.TypeOf(svc).MethodByName(test.preRead)
			require.True(t, ok, "mock has no method %s", test.preRead)
			svc.On(test.preRead, mock.Anything, mock.Anything).Return(reflect.Zero(preRead.Type.Out(0)).Interface(), test.notFound)

			method := reflect.ValueOf(publisher).MethodByName(test.method)
			require.True(t, method.IsValid(), "publisher has no method %s", test.method)
			input := reflect.New(method.Type().In(1)).Elem()
			out := method.Call([]reflect.Value{reflect.ValueOf(context.Background()), input})

			err, _ := out[len(out)-1].Interface().(error)
			assert.True(t, err == test.notFound, "expected %v unwrapped, got %v", test.notFound, err)
		})
	}
}

func caPublisher() (any, serviceMocker) {
	svc := new(svcmock.MockCAService)
	return NewCAEventBusPublisher(new(CloudEventPublisherMock))(svc), svc
}

func devicePublisher() (any, serviceMocker) {
	svc := new(svcmock.MockDeviceManagerService)
	return NewDeviceEventPublisher(new(CloudEventPublisherMock))(svc), svc
}

func dmsPublisher() (any, serviceMocker) {
	svc := new(svcmock.MockDMSManagerService)
	return NewDMSEventPublisher(new(CloudEventPublisherMock))(svc), svc
}

func kmsPublisher() (any, serviceMocker) {
	svc := new(svcmock.MockKMSService)
	return NewKMSEventBusPublisher(new(CloudEventPublisherMock))(svc), svc
}
