package middlewares_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	auditmw "github.com/lamassuiot/lamassuiot/v4/backend/pkg/middlewares/audit"
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/middlewares/eventpub"
	otelmw "github.com/lamassuiot/lamassuiot/v4/backend/pkg/middlewares/otel"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	svcmock "github.com/lamassuiot/lamassuiot/v4/core/pkg/services/mock"
	"github.com/stretchr/testify/mock"
)

// errService is what the wrapped service fails with, whichever method a middleware calls.
var errService = errors.New("service error")

var errorType = reflect.TypeOf((*error)(nil)).Elem()

type serviceMock interface {
	On(string, ...interface{}) *mock.Call
}

type noopPublisher struct{}

func (noopPublisher) PublishCloudEvent(context.Context, interface{}) {}

var audit = auditmw.AuditPublisher{ICloudEventPublisher: noopPublisher{}}

// The controllers map service errors to status codes by identity, so a middleware that wraps or
// replaces an error turns, for instance, a 404 into a 500. Every method of every middleware must
// return the service's error unchanged, including the errors of the reads the event publishers make
// to publish a resource's previous state.
func TestMiddlewaresReturnServiceErrorsUnchanged(t *testing.T) {
	for _, chain := range []struct {
		service string
		iface   reflect.Type
		newMock func() serviceMock
		// mockReturns holds the first value to return for the mock methods that expect another
		// type than the interface method returns.
		mockReturns map[string]any
		middlewares map[string]func(serviceMock) any
	}{
		{
			service:     "CA",
			iface:       reflect.TypeOf((*services.CAService)(nil)).Elem(),
			newMock:     func() serviceMock { return new(svcmock.MockCAService) },
			mockReturns: map[string]any{"SignatureSign": (*[]byte)(nil)},
			middlewares: map[string]func(serviceMock) any{
				"audit": func(m serviceMock) any { return auditmw.NewCAAuditEventBusPublisher(audit)(m.(*svcmock.MockCAService)) },
				"eventpub": func(m serviceMock) any {
					return eventpub.NewCAEventBusPublisher(noopPublisher{})(m.(*svcmock.MockCAService))
				},
				"otel": func(m serviceMock) any { return otelmw.NewCAOTelTracer()(m.(*svcmock.MockCAService)) },
			},
		},
		{
			service:     "CRL",
			iface:       reflect.TypeOf((*services.CRLService)(nil)).Elem(),
			newMock:     func() serviceMock { return new(svcmock.MockVAService) },
			mockReturns: map[string]any{"GetVARoles": &[]*models.VARole{}},
			middlewares: map[string]func(serviceMock) any{
				"audit": func(m serviceMock) any { return auditmw.NewCRLAuditEventPublisher(audit)(m.(*svcmock.MockVAService)) },
				"eventpub": func(m serviceMock) any {
					return eventpub.NewCRLEventPublisher(noopPublisher{})(m.(*svcmock.MockVAService))
				},
				"otel": func(m serviceMock) any { return otelmw.NewCRLOTelTracer()(m.(*svcmock.MockVAService)) },
			},
		},
		{
			service: "DeviceManager",
			iface:   reflect.TypeOf((*services.DeviceManagerService)(nil)).Elem(),
			newMock: func() serviceMock { return new(svcmock.MockDeviceManagerService) },
			middlewares: map[string]func(serviceMock) any{
				"audit": func(m serviceMock) any {
					return auditmw.NewDeviceAuditEventPublisher(audit)(m.(*svcmock.MockDeviceManagerService))
				},
				"eventpub": func(m serviceMock) any {
					return eventpub.NewDeviceEventPublisher(noopPublisher{})(m.(*svcmock.MockDeviceManagerService))
				},
			},
		},
		{
			service: "DMSManager",
			iface:   reflect.TypeOf((*services.DMSManagerService)(nil)).Elem(),
			newMock: func() serviceMock { return new(svcmock.MockDMSManagerService) },
			middlewares: map[string]func(serviceMock) any{
				"audit": func(m serviceMock) any {
					return auditmw.NewDmsAuditEventPublisher(audit)(m.(*svcmock.MockDMSManagerService))
				},
				"eventpub": func(m serviceMock) any {
					return eventpub.NewDMSEventPublisher(noopPublisher{})(m.(*svcmock.MockDMSManagerService))
				},
			},
		},
		{
			service: "KMS",
			iface:   reflect.TypeOf((*services.KMSService)(nil)).Elem(),
			newMock: func() serviceMock { return new(svcmock.MockKMSService) },
			middlewares: map[string]func(serviceMock) any{
				"audit": func(m serviceMock) any {
					return auditmw.NewKMSAuditEventBusPublisher(audit)(m.(*svcmock.MockKMSService))
				},
				"eventpub": func(m serviceMock) any {
					return eventpub.NewKMSEventBusPublisher(noopPublisher{})(m.(*svcmock.MockKMSService))
				},
				"otel": func(m serviceMock) any { return otelmw.NewKMSOTelTracer()(m.(*svcmock.MockKMSService)) },
			},
		},
	} {
		for name, wrap := range chain.middlewares {
			t.Run(chain.service+"/"+name, func(t *testing.T) {
				for i := 0; i < chain.iface.NumMethod(); i++ {
					method := chain.iface.Method(i)
					if method.Type.NumOut() == 0 || method.Type.Out(method.Type.NumOut()-1) != errorType {
						continue
					}

					err := callWithFailingService(chain.iface, chain.newMock(), chain.mockReturns, wrap, method.Name)
					if err != errService {
						t.Errorf("%s returned %v, want the service error unchanged", method.Name, err)
					}
				}
			})
		}
	}
}

// callWithFailingService calls a middleware method with zero inputs while every method of the
// wrapped service fails with errService, and returns the method's error.
func callWithFailingService(iface reflect.Type, svc serviceMock, mockReturns map[string]any, wrap func(serviceMock) any, methodName string) (err error) {
	for i := 0; i < iface.NumMethod(); i++ {
		method := iface.Method(i).Type
		args := make([]interface{}, method.NumIn())
		for j := range args {
			args[j] = mock.Anything
		}
		returns := make([]interface{}, method.NumOut())
		for j := 0; j < method.NumOut()-1; j++ {
			returns[j] = reflect.Zero(method.Out(j)).Interface()
		}
		if value, ok := mockReturns[iface.Method(i).Name]; ok {
			returns[0] = value
		}
		returns[method.NumOut()-1] = errService
		svc.On(iface.Method(i).Name, args...).Return(returns...)
	}

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()

	method := reflect.ValueOf(wrap(svc)).MethodByName(methodName)
	in := make([]reflect.Value, method.Type().NumIn())
	in[0] = reflect.ValueOf(context.Background())
	for j := 1; j < len(in); j++ {
		in[j] = reflect.New(method.Type().In(j)).Elem()
	}
	out := method.Call(in)
	err, _ = out[len(out)-1].Interface().(error)
	return err
}
