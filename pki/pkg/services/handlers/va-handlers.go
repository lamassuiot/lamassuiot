package handlers

import (
	"context"
	"fmt"

	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services/eventhandling"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
)

func NewVAEventHandler(l *logrus.Entry, svc services.CRLService) *eventhandling.CloudEventHandler {
	return &eventhandling.CloudEventHandler{
		Logger: l,
		DispatchMap: map[string]func(context.Context, *event.Event) error{
			string(models.EventCreateCAKey):                func(ctx context.Context, m *event.Event) error { return createCAHandler(ctx, m, svc, l) },
			string(models.EventUpdateCertificateStatusKey): func(ctx context.Context, m *event.Event) error { return updateCertificateStatus(ctx, m, svc, l) },
		},
	}
}

func createCAHandler(ctx context.Context, event *event.Event, crlSvc services.CRLService, lMessaging *logrus.Entry) error {
	ca, err := helpers.GetEventBody[models.CACertificate](event)
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

func updateCertificateStatus(ctx context.Context, event *event.Event, crlSvc services.CRLService, lMessaging *logrus.Entry) error {
	cert, err := helpers.GetEventBody[models.UpdateModel[models.Certificate]](event)
	if err != nil {
		err = fmt.Errorf("could not decode cloud event: %s", err)
		lMessaging.Error(err)
		return err
	}

	ski := cert.Updated.SubjectKeyID
	aki := cert.Updated.AuthorityKeyID

	cn := cert.Updated.Certificate.Subject.CommonName
	icn := cert.Updated.Certificate.Issuer.CommonName

	// Check if this is a certificate being reactivated from CertificateHold
	isReactivationFromHold := cert.Previous.Status == models.StatusRevoked &&
		cert.Previous.RevocationReason == ocsp.CertificateHold &&
		cert.Updated.Status == models.StatusActive

	// Check if this is a normal revocation
	isRevocation := cert.Updated.Status == models.StatusRevoked

	// Regenerate CRL if certificate is revoked OR reactivated from CertificateHold
	if isRevocation || isReactivationFromHold {
		action := "revocation"
		if isReactivationFromHold {
			action = "reactivation from CertificateHold"
		}

		lMessaging.Infof("Certificate %s %s - %s %s is being processed for CRL update due to %s", cn, ski, icn, aki, action)

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
			lMessaging.Infof("CRL regenerated for CA %s due to certificate %s", aki, action)
		} else {
			lMessaging.Infof("CRL regeneration disabled for CA %s, skipping CRL update", aki)
		}
	}

	return nil
}
