package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type vaRoleInitializer struct {
	services.CRLService
	initializedSKIs []string
	err             error
}

func (svc *vaRoleInitializer) InitCRLRole(_ context.Context, ski string) (*models.VARole, error) {
	svc.initializedSKIs = append(svc.initializedSKIs, ski)
	if svc.err != nil {
		return nil, svc.err
	}
	return &models.VARole{CASubjectKeyID: ski}, nil
}

func vaEventMessage(t *testing.T, eventType models.EventType, body any) *message.Message {
	t.Helper()
	e := event.New()
	e.SetID("ca-event")
	e.SetSource("ca-service")
	e.SetType(string(eventType))
	require.NoError(t, e.SetData("application/json", body))
	payload, err := json.Marshal(e)
	require.NoError(t, err)
	return message.NewMessage(e.ID(), payload)
}

func vaTestLogger() *logrus.Entry {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return logrus.NewEntry(logger)
}

func TestVAEventHandlerInitializesCARoles(t *testing.T) {
	for _, tc := range []struct {
		name      string
		eventType models.EventType
		caType    models.CertificateType
	}{
		{name: "created CA", eventType: models.EventCreateCAKey, caType: models.CertificateTypeManaged},
		{name: "imported CA with key", eventType: models.EventImportCAKey, caType: models.CertificateTypeImportedWithKey},
		{name: "imported CA without key", eventType: models.EventImportCAKey, caType: models.CertificateTypeImportedWithoutKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := &vaRoleInitializer{}
			handler := NewVAEventHandler(vaTestLogger(), svc)
			ca := models.CACertificate{
				ID: "test-ca",
				Certificate: models.Certificate{
					SubjectKeyID: "child-ski", AuthorityKeyID: "parent-ski", Type: tc.caType,
				},
			}
			require.NoError(t, handler.HandleMessage(vaEventMessage(t, tc.eventType, ca)))
			// The role belongs to the imported CA's own key, not its issuer's key.
			require.Equal(t, []string{ca.Certificate.SubjectKeyID}, svc.initializedSKIs)
		})
	}
}

func TestVAImportEventReturnsInitializationError(t *testing.T) {
	svc := &vaRoleInitializer{err: errors.New("VA storage unavailable")}
	handler := NewVAEventHandler(vaTestLogger(), svc)
	ca := models.CACertificate{ID: "imported-ca", Certificate: models.Certificate{SubjectKeyID: "imported-ski"}}
	err := handler.HandleMessage(vaEventMessage(t, models.EventImportCAKey, ca))
	require.ErrorContains(t, err, "could not initialize CRL role")
	require.ErrorContains(t, err, svc.err.Error())
	require.Equal(t, []string{ca.Certificate.SubjectKeyID}, svc.initializedSKIs)
}

func TestVAImportEventRejectsInvalidCABody(t *testing.T) {
	svc := &vaRoleInitializer{}
	handler := NewVAEventHandler(vaTestLogger(), svc)
	err := handler.HandleMessage(vaEventMessage(t, models.EventImportCAKey, "invalid CA payload"))
	require.ErrorContains(t, err, "could not decode cloud event")
	require.Empty(t, svc.initializedSKIs)
}
