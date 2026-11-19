package eventpub

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	svcmock "github.com/lamassuiot/lamassuiot/v4/core/pkg/services/mock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
)

// The subject of the CRL events is the ID of the CA, not its SKI: CAs sharing a key share the SKI.
func TestCRLEventPublisherSubjectsUseCAID(t *testing.T) {
	for _, tc := range []struct {
		name      string
		eventType models.EventType
		call      func(svc services.CRLService)
		setup     func(svc *svcmock.MockVAService)
	}{
		{
			name: "init", eventType: models.EventInitCRLSettings,
			setup: func(svc *svcmock.MockVAService) {
				svc.On("InitCRLSettings", mock.Anything, "ca-1").Return(&models.CRLSettings{}, nil)
			},
			call: func(svc services.CRLService) { _, _ = svc.InitCRLSettings(context.Background(), "ca-1") },
		},
		{
			name: "update", eventType: models.EventUpdateCRLSettings,
			setup: func(svc *svcmock.MockVAService) {
				svc.On("UpdateCRLSettings", mock.Anything, mock.Anything).Return(&models.CRLSettings{}, nil)
			},
			call: func(svc services.CRLService) {
				_, _ = svc.UpdateCRLSettings(context.Background(), services.UpdateCRLSettingsInput{CAID: "ca-1"})
			},
		},
		{
			name: "finalize", eventType: models.EventFinalizeCRLSettings,
			setup: func(svc *svcmock.MockVAService) {
				svc.On("FinalizeCRLSettings", mock.Anything, mock.Anything).Return(&models.CRLSettings{}, nil)
			},
			call: func(svc services.CRLService) {
				_, _ = svc.FinalizeCRLSettings(context.Background(), services.FinalizeCRLSettingsInput{CAID: "ca-1"})
			},
		},
		{
			name: "archive", eventType: models.EventArchiveCRLSettings,
			setup: func(svc *svcmock.MockVAService) {
				svc.On("ArchiveCRLSettings", mock.Anything, mock.Anything).Return(&models.CRLSettings{}, nil)
			},
			call: func(svc services.CRLService) {
				_, _ = svc.ArchiveCRLSettings(context.Background(), services.ArchiveCRLSettingsInput{CAID: "ca-1"})
			},
		},
		{
			name: "delete", eventType: models.EventDeleteCRLSettings,
			setup: func(svc *svcmock.MockVAService) {
				svc.On("DeleteCRLSettings", mock.Anything, mock.Anything).Return(nil)
			},
			call: func(svc services.CRLService) {
				_ = svc.DeleteCRLSettings(context.Background(), services.DeleteCRLSettingsInput{CAID: "ca-1"})
			},
		},
		{
			name: "calculate", eventType: models.EventCreateCRL,
			setup: func(svc *svcmock.MockVAService) {
				svc.On("CalculateCRL", mock.Anything, mock.Anything).Return(&x509.RevocationList{}, nil)
			},
			call: func(svc services.CRLService) {
				_, _ = svc.CalculateCRL(context.Background(), services.CalculateCRLInput{CAID: "ca-1"})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := new(svcmock.MockVAService)
			tc.setup(next)
			pub := new(CloudEventPublisherMock)
			pub.On("PublishCloudEvent", mock.MatchedBy(func(ctx context.Context) bool {
				return ctx.Value(core.LamassuContextKeyEventSubject) == "crl/ca-1" && ctx.Value(core.LamassuContextKeyEventType) == tc.eventType
			}), mock.Anything).Return()

			tc.call(NewCRLEventPublisher(pub, testLogger())(next))

			pub.AssertExpectations(t)
		})
	}
}

// A failed lifecycle operation publishes nothing, and reconciling publishes nothing itself: its changes go through the
// lifecycle operations, which publish their own events.
func TestCRLEventPublisherLifecycleWithoutEvents(t *testing.T) {
	next := new(svcmock.MockVAService)
	next.On("FinalizeCRLSettings", mock.Anything, mock.Anything).Return(nil, errors.New("boom"))
	next.On("ArchiveCRLSettings", mock.Anything, mock.Anything).Return(nil, errors.New("boom"))
	next.On("DeleteCRLSettings", mock.Anything, mock.Anything).Return(errors.New("boom"))
	next.On("ReconcileCRLSettings", mock.Anything, mock.Anything).Return(&models.CRLSettings{}, nil)
	pub := new(CloudEventPublisherMock)
	svc := NewCRLEventPublisher(pub, testLogger())(next)

	_, _ = svc.FinalizeCRLSettings(context.Background(), services.FinalizeCRLSettingsInput{CAID: "ca-1"})
	_, _ = svc.ArchiveCRLSettings(context.Background(), services.ArchiveCRLSettingsInput{CAID: "ca-1"})
	_ = svc.DeleteCRLSettings(context.Background(), services.DeleteCRLSettingsInput{CAID: "ca-1"})
	_, _ = svc.ReconcileCRLSettings(context.Background(), services.ReconcileCRLSettingsInput{CAID: "ca-1"})

	next.AssertExpectations(t)
	pub.AssertNotCalled(t, "PublishCloudEvent", mock.Anything, mock.Anything)
}

// A CA without a key gets no CRL settings: InitCRLSettings succeeds with nothing to announce.
func TestCRLEventPublisherInitWithoutSettingsPublishesNothing(t *testing.T) {
	next := new(svcmock.MockVAService)
	next.On("InitCRLSettings", mock.Anything, "ca-1").Return(nil, nil)
	pub := new(CloudEventPublisherMock)
	svc := NewCRLEventPublisher(pub, testLogger())(next)

	_, err := svc.InitCRLSettings(context.Background(), "ca-1")

	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	pub.AssertNotCalled(t, "PublishCloudEvent", mock.Anything, mock.Anything)
}

func finalizeEventMatcher(eventType models.EventType) any {
	return mock.MatchedBy(func(ctx context.Context) bool {
		return ctx.Value(core.LamassuContextKeyEventSubject) == "crl/ca-1" && ctx.Value(core.LamassuContextKeyEventType) == eventType
	})
}

// The final CRL is a CRL publication like any other: it announces va.role.crl.create with the CRL, besides the
// va.crl-settings.finalize event of the settings.
func TestCRLEventPublisherFinalCRLPublishesCreateCRL(t *testing.T) {
	version := big.NewInt(7)
	finalCRL := &x509.RevocationList{Number: version}
	finalSettings := &models.CRLSettings{CAID: "ca-1", Status: models.CRLSettingsFinal, LatestCRL: models.LatestCRLMeta{Version: models.BigInt{Int: version}}}

	next := new(svcmock.MockVAService)
	next.On("GetCRLSettings", mock.Anything, services.GetCRLSettingsInput{CAID: "ca-1"}).Return(&models.CRLSettings{CAID: "ca-1", Status: models.CRLSettingsActive}, nil)
	next.On("FinalizeCRLSettings", mock.Anything, mock.Anything).Return(finalSettings, nil)
	next.On("GetCRL", mock.Anything, services.GetCRLInput{ID: "ca-1", CRLVersion: version}).Return(finalCRL, nil)
	pub := new(CloudEventPublisherMock)
	pub.On("PublishCloudEvent", finalizeEventMatcher(models.EventCreateCRL), finalCRL).Return().Once()
	pub.On("PublishCloudEvent", finalizeEventMatcher(models.EventFinalizeCRLSettings), finalSettings).Return().Once()

	_, err := NewCRLEventPublisher(pub, testLogger())(next).FinalizeCRLSettings(context.Background(), services.FinalizeCRLSettingsInput{CAID: "ca-1", FinalCRL: true, FinalCRLNextUpdate: time.Now().Add(time.Hour)})

	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	pub.AssertExpectations(t)
}

// Finalizing settings that were already FINAL issues no CRL, so a retried event announces none.
func TestCRLEventPublisherFinalizingFinalSettingsPublishesNoCreateCRL(t *testing.T) {
	version := big.NewInt(7)
	finalSettings := &models.CRLSettings{CAID: "ca-1", Status: models.CRLSettingsFinal, LatestCRL: models.LatestCRLMeta{Version: models.BigInt{Int: version}}}

	next := new(svcmock.MockVAService)
	next.On("GetCRLSettings", mock.Anything, mock.Anything).Return(finalSettings, nil)
	next.On("FinalizeCRLSettings", mock.Anything, mock.Anything).Return(finalSettings, nil)
	pub := new(CloudEventPublisherMock)
	pub.On("PublishCloudEvent", finalizeEventMatcher(models.EventFinalizeCRLSettings), finalSettings).Return().Once()

	_, _ = NewCRLEventPublisher(pub, testLogger())(next).FinalizeCRLSettings(context.Background(), services.FinalizeCRLSettingsInput{CAID: "ca-1", FinalCRL: true, FinalCRLNextUpdate: time.Now().Add(time.Hour)})

	pub.AssertExpectations(t)
	pub.AssertNumberOfCalls(t, "PublishCloudEvent", 1)
}

// An unknown status before the call counts as "will issue": a duplicate CRL event is harmless, a lost one is not.
func TestCRLEventPublisherFinalCRLPublishesCreateCRLWhenTheStatusReadFails(t *testing.T) {
	version := big.NewInt(7)
	finalCRL := &x509.RevocationList{Number: version}
	finalSettings := &models.CRLSettings{CAID: "ca-1", Status: models.CRLSettingsFinal, LatestCRL: models.LatestCRLMeta{Version: models.BigInt{Int: version}}}

	next := new(svcmock.MockVAService)
	next.On("GetCRLSettings", mock.Anything, mock.Anything).Return(nil, errors.New("storage unavailable"))
	next.On("FinalizeCRLSettings", mock.Anything, mock.Anything).Return(finalSettings, nil)
	next.On("GetCRL", mock.Anything, mock.Anything).Return(finalCRL, nil)
	pub := new(CloudEventPublisherMock)
	pub.On("PublishCloudEvent", finalizeEventMatcher(models.EventCreateCRL), finalCRL).Return().Once()
	pub.On("PublishCloudEvent", finalizeEventMatcher(models.EventFinalizeCRLSettings), finalSettings).Return().Once()

	_, _ = NewCRLEventPublisher(pub, testLogger())(next).FinalizeCRLSettings(context.Background(), services.FinalizeCRLSettingsInput{CAID: "ca-1", FinalCRL: true, FinalCRLNextUpdate: time.Now().Add(time.Hour)})

	pub.AssertExpectations(t)
}

func testLogger() *logrus.Entry {
	l := logrus.New()
	l.SetOutput(&bytes.Buffer{})
	return logrus.NewEntry(l)
}

// A final CRL whose re-read fails cannot be announced: the failure is logged, not swallowed, and the finalize event
// still goes out.
func TestCRLEventPublisherLogsWhenTheFinalCRLCannotBeRead(t *testing.T) {
	version := big.NewInt(7)
	finalSettings := &models.CRLSettings{CAID: "ca-1", Status: models.CRLSettingsFinal, LatestCRL: models.LatestCRLMeta{Version: models.BigInt{Int: version}}}

	next := new(svcmock.MockVAService)
	next.On("GetCRLSettings", mock.Anything, mock.Anything).Return(&models.CRLSettings{CAID: "ca-1", Status: models.CRLSettingsActive}, nil)
	next.On("FinalizeCRLSettings", mock.Anything, mock.Anything).Return(finalSettings, nil)
	next.On("GetCRL", mock.Anything, mock.Anything).Return((*x509.RevocationList)(nil), errors.New("bucket unavailable"))
	pub := new(CloudEventPublisherMock)
	pub.On("PublishCloudEvent", finalizeEventMatcher(models.EventFinalizeCRLSettings), finalSettings).Return().Once()
	var logs bytes.Buffer
	l := logrus.New()
	l.SetOutput(&logs)

	_, _ = NewCRLEventPublisher(pub, logrus.NewEntry(l))(next).FinalizeCRLSettings(context.Background(), services.FinalizeCRLSettingsInput{CAID: "ca-1", FinalCRL: true, FinalCRLNextUpdate: time.Now().Add(time.Hour)})

	pub.AssertExpectations(t)
	pub.AssertNumberOfCalls(t, "PublishCloudEvent", 1)
	if !strings.Contains(logs.String(), "ca-1") || !strings.Contains(logs.String(), "bucket unavailable") {
		t.Fatalf("the failure to read the final CRL was not logged: %q", logs.String())
	}
}
