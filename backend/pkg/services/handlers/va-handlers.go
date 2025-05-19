package handlers

import (
	"context"
	"fmt"

	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	beService "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services/eventhandling"
	"github.com/sirupsen/logrus"
)

func NewVAEventHandler(l *logrus.Entry, crlSvc *beService.CRLServiceBackend) *eventhandling.CloudEventHandler {
	return &eventhandling.CloudEventHandler{
		Logger: l,
		DispatchMap: map[string]func(context.Context, *event.Event) error{
			string(models.EventCreateCAKey):                func(ctx context.Context, m *event.Event) error { return createCAHandler(ctx, m, crlSvc, l) },
			string(models.EventUpdateCertificateStatusKey): func(ctx context.Context, m *event.Event) error { return updateCertificateStatus(ctx, m, crlSvc, l) },
		},
	}
}

func createCAHandler(ctx context.Context, event *event.Event, crlSvc *beService.CRLServiceBackend, lMessaging *logrus.Entry) error {

	ca, err := chelpers.GetEventBody[models.CACertificate](event)
	if err != nil {
		err = fmt.Errorf("could not decode cloud event: %s", err)
		lMessaging.Error(err)
		return err
	}

	_, err = crlSvc.InitCRLRole(ctx, ca.Certificate.SubjectKeyID)

	if err != nil {
		err = fmt.Errorf("could not initialize CRL role: %s", err)
		lMessaging.Error(err)
	}

	lMessaging.Infof("CRL role initialized for CA %s", ca.ID)

	return nil
}

func updateCertificateStatus(ctx context.Context, event *event.Event, crlSvc *beService.CRLServiceBackend, lMessaging *logrus.Entry) error {
	cert, err := chelpers.GetEventBody[models.UpdateModel[models.Certificate]](event)
	if err != nil {
		err = fmt.Errorf("could not decode cloud event: %s", err)
		lMessaging.Error(err)
		return err
	}

	ski := helpers.FormatHexWithColons(cert.Updated.Certificate.SubjectKeyId)
	aki := helpers.FormatHexWithColons(cert.Updated.Certificate.AuthorityKeyId)
	cn := cert.Updated.Certificate.Subject.CommonName
	icn := cert.Updated.Certificate.Issuer.CommonName

	if cert.Updated.Status == models.StatusRevoked {
		role, err := crlSvc.GetVARole(ctx, services.GetVARoleInput{
			CASubjectKeyID: aki,
		})
		if err != nil {
			err = fmt.Errorf("could not get VA role for certificate %s %s - %s %s: %s", cn, ski, icn, aki, err)
			lMessaging.Error(err)
			return err
		}

		if role.CRLOptions.RegenerateOnRevoke {
			_, err = crlSvc.CalculateCRL(ctx, services.CalculateCRLInput{
				CASubjectKeyID: aki,
			})
			if err != nil {
				err = fmt.Errorf("could not calculate CRL for certificate %s %s - %s %s: %s", cn, ski, icn, aki, err)
				lMessaging.Error(err)
				return err
			}
		}
	}

	return nil
}
