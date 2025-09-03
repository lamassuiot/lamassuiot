package handlers

import (
	"context"
	"fmt"

	"github.com/cloudevents/sdk-go/v2/event"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services/eventhandling"
	"github.com/sirupsen/logrus"
)

func NewVAEventHandler(l *logrus.Entry, crlSvc services.CRLService) *eventhandling.CloudEventHandler {
	return &eventhandling.CloudEventHandler{
		Logger: l,
		DispatchMap: map[string]func(*event.Event) error{
			string(models.EventCreateCAKey):                func(m *event.Event) error { return createCAHandler(m, crlSvc, l) },
			string(models.EventUpdateCertificateStatusKey): func(m *event.Event) error { return updateCertificateStatus(m, crlSvc, l) },
		},
	}
}

func createCAHandler(event *event.Event, crlSvc services.CRLService, lMessaging *logrus.Entry) error {
	ctx := context.Background()

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
		return err
	}

	lMessaging.Infof("CRL role initialized for CA %s", ca.ID)

	return nil
}

func updateCertificateStatus(event *event.Event, crlSvc services.CRLService, lMessaging *logrus.Entry) error {
	ctx := context.Background()

	cert, err := chelpers.GetEventBody[models.UpdateModel[models.Certificate]](event)
	if err != nil {
		err = fmt.Errorf("could not decode cloud event: %s", err)
		lMessaging.Error(err)
		return err
	}

	ski := cert.Updated.SubjectKeyID
	aki := cert.Updated.AuthorityKeyID

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
