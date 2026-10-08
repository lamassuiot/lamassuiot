package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type vaRoleInitializer struct {
	services.CRLService
	initializedSKIs []string
	err             error
	existingRoles   map[string]bool
	getErr          error
}

func (svc *vaRoleInitializer) GetVARole(_ context.Context, input services.GetVARoleInput) (*models.VARole, error) {
	if svc.getErr != nil {
		return nil, svc.getErr
	}
	if svc.existingRoles[input.CASubjectKeyID] {
		return &models.VARole{CASubjectKeyID: input.CASubjectKeyID}, nil
	}
	return nil, errs.ErrVARoleNotFound
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
		skipped   bool
	}{
		{name: "created CA", eventType: models.EventCreateCAKey, caType: models.CertificateTypeManaged},
		{name: "imported CA with key", eventType: models.EventImportCAKey, caType: models.CertificateTypeImportedWithKey},
		{name: "imported CA without key", eventType: models.EventImportCAKey, caType: models.CertificateTypeImportedWithoutKey, skipped: true},
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
			if tc.skipped {
				// Keyless CAs cannot sign a CRL, so no role must be created.
				require.Empty(t, svc.initializedSKIs)
				return
			}
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

func TestVAImportEventSkipsExistingRole(t *testing.T) {
	svc := &vaRoleInitializer{existingRoles: map[string]bool{"imported-ski": true}}
	handler := NewVAEventHandler(vaTestLogger(), svc)
	ca := models.CACertificate{ID: "imported-ca", Certificate: models.Certificate{SubjectKeyID: "imported-ski"}}
	require.NoError(t, handler.HandleMessage(vaEventMessage(t, models.EventImportCAKey, ca)))
	require.Empty(t, svc.initializedSKIs)
}

func TestVAImportEventReturnsRoleLookupError(t *testing.T) {
	svc := &vaRoleInitializer{getErr: errors.New("VA storage unavailable")}
	handler := NewVAEventHandler(vaTestLogger(), svc)
	ca := models.CACertificate{ID: "imported-ca", Certificate: models.Certificate{SubjectKeyID: "imported-ski"}}
	err := handler.HandleMessage(vaEventMessage(t, models.EventImportCAKey, ca))
	require.ErrorContains(t, err, "could not check existing CRL role")
	require.Empty(t, svc.initializedSKIs)
}

func TestVAImportEventIgnoresRoleCreatedConcurrently(t *testing.T) {
	svc := &vaRoleInitializer{err: errs.ErrVARoleAlreadyExists}
	handler := NewVAEventHandler(vaTestLogger(), svc)
	ca := models.CACertificate{ID: "imported-ca", Certificate: models.Certificate{SubjectKeyID: "imported-ski"}}
	require.NoError(t, handler.HandleMessage(vaEventMessage(t, models.EventImportCAKey, ca)))
	require.Equal(t, []string{"imported-ski"}, svc.initializedSKIs)
}
