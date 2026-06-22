package handlers

import (
	"context"
	"fmt"

	"github.com/cloudevents/sdk-go/v2/event"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services/eventhandling"
	"github.com/sirupsen/logrus"
)

func NewCAKMSEventHandler(l *logrus.Entry, svc services.CAService) *eventhandling.CloudEventHandler {
	return &eventhandling.CloudEventHandler{
		Logger: l,
		DispatchMap: map[string]func(context.Context, *event.Event) error{
			string(models.EventDeleteKMSKey): func(ctx context.Context, e *event.Event) error {
				return handleKMSKeyDeleted(ctx, e, svc, l)
			},
		},
	}
}

func handleKMSKeyDeleted(ctx context.Context, e *event.Event, svc services.CAService, l *logrus.Entry) error {
	keyInput, err := chelpers.GetEventBody[services.GetKeyInput](e)
	if err != nil {
		return fmt.Errorf("could not decode kms.delete event body: %w", err)
	}

	keyID := keyInput.Identifier
	l.Infof("KMS key %s deleted: clearing has_private_key on bound certificates and CAs", keyID)

	skidFilter := &resources.QueryParameters{
		Filters: []resources.FilterOption{
			{Field: "subject_key_id", FilterOperation: resources.StringEqual, Value: keyID},
			{Field: "has_private_key", FilterOperation: resources.EnumEqual, Value: "true"},
		},
	}

	// Clear has_private_key on all leaf certificates whose key was just deleted.
	_, certErr := svc.GetCertificates(ctx, services.GetCertificatesInput{
		ListInput: resources.ListInput[models.Certificate]{
			ExhaustiveRun:   true,
			QueryParameters: skidFilter,
			ApplyFunc: func(cert models.Certificate) {
				if _, uErr := svc.UpdateCertificateHasPrivateKey(ctx, services.UpdateCertificateHasPrivateKeyInput{
					SerialNumber:  cert.SerialNumber,
					HasPrivateKey: false,
				}); uErr != nil {
					l.Errorf("could not clear has_private_key for certificate %s: %s", cert.SerialNumber, uErr)
				}
			},
		},
	})
	if certErr != nil {
		l.Errorf("could not list certificates for deleted key %s: %s", keyID, certErr)
	}

	// Clear has_private_key on all CA certificates whose key was just deleted.
	_, caErr := svc.GetCAs(ctx, services.GetCAsInput{
		ExhaustiveRun: true,
		QueryParameters: &resources.QueryParameters{
			Filters: []resources.FilterOption{
				{Field: "subject_key_id", FilterOperation: resources.StringEqual, Value: keyID},
				{Field: "has_private_key", FilterOperation: resources.EnumEqual, Value: "true"},
			},
		},
		ApplyFunc: func(ca models.CACertificate) {
			if _, uErr := svc.UpdateCAHasPrivateKey(ctx, services.UpdateCAHasPrivateKeyInput{
				CAID:          ca.ID,
				HasPrivateKey: false,
			}); uErr != nil {
				l.Errorf("could not clear has_private_key for CA %s: %s", ca.ID, uErr)
			}
		},
	})
	if caErr != nil {
		l.Errorf("could not list CAs for deleted key %s: %s", keyID, caErr)
	}

	if certErr != nil || caErr != nil {
		return fmt.Errorf("errors while clearing has_private_key for deleted key %s (cert: %v, ca: %v)", keyID, certErr, caErr)
	}

	return nil
}
