package handlers

import (
	"context"
	"errors"
	"fmt"

	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services/eventhandling"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
)

func NewVAEventHandler(l *logrus.Entry, svc services.CRLService) *eventhandling.CloudEventHandler {
	return &eventhandling.CloudEventHandler{
		Logger: l,
		DispatchMap: map[string]func(context.Context, *event.Event) error{
			string(models.EventCreateCAKey):                func(ctx context.Context, m *event.Event) error { return createCAHandler(ctx, m, svc, l) },
			string(models.EventReissueCAKey):               func(ctx context.Context, m *event.Event) error { return reissueCAHandler(ctx, m, svc, l) },
			string(models.EventUpdateCertificateStatusKey): func(ctx context.Context, m *event.Event) error { return updateCertificateStatus(ctx, m, svc, l) },
		},
	}
}

// reissueCAHandler moves the CRL signer of the VA role to the reissued CA certificate, then regenerates the CRL
// so it is signed by that certificate right away. Only a role signed by the CA certificate being superseded is
// updated: any other signer was chosen on purpose and is kept.
func reissueCAHandler(ctx context.Context, event *event.Event, crlSvc services.CRLService, lMessaging *logrus.Entry) error {
	ca, err := helpers.GetEventBody[models.UpdateModel[models.CACertificate]](event)
	if err != nil {
		err = fmt.Errorf("could not decode cloud event: %s", err)
		lMessaging.Error(err)
		return err
	}

	ski := ca.Previous.Certificate.SubjectKeyID
	prevSN := ca.Previous.Certificate.SerialNumber
	newSN := ca.Updated.Certificate.SerialNumber

	role, err := crlSvc.GetVARole(ctx, services.GetVARoleInput{CASubjectKeyID: ski})
	if errors.Is(err, errs.ErrVARoleNotFound) {
		lMessaging.Warnf("reissued CA %s has no VA role %s: no CRL signer to update", ca.Updated.ID, ski)
		return nil
	}
	if err != nil {
		err = fmt.Errorf("could not get VA role for reissued CA %s: %w", ca.Updated.ID, err)
		lMessaging.Error(err)
		return err
	}

	if role.CRLOptions.SignerCertificateSerialNumber != prevSN {
		lMessaging.Infof("VA role %s is signed by certificate %s, not by the reissued certificate %s of CA %s: keeping its CRL signer", ski, role.CRLOptions.SignerCertificateSerialNumber, prevSN, ca.Updated.ID)
		return nil
	}

	crlOptions := role.CRLOptions
	crlOptions.SignerCertificateSerialNumber = newSN
	_, err = crlSvc.UpdateVARole(ctx, services.UpdateVARoleInput{
		CASubjectKeyID: ski,
		CRLRole:        crlOptions,
	})
	if errors.Is(err, errs.ErrValidateBadRequest) {
		lMessaging.Warnf("reissued certificate %s of CA %s cannot sign CRLs (it needs the cRLSign key usage): VA role %s keeps signer %s", newSN, ca.Updated.ID, ski, prevSN)
		return nil
	}
	if err != nil {
		err = fmt.Errorf("could not update CRL signer of VA role %s to certificate %s: %w", ski, newSN, err)
		lMessaging.Error(err)
		return err
	}

	lMessaging.Infof("VA role %s CRL signer moved from certificate %s to reissued certificate %s", ski, prevSN, newSN)

	_, err = crlSvc.CalculateCRL(ctx, services.CalculateCRLInput{CASubjectKeyID: ski})
	if err != nil {
		err = fmt.Errorf("could not calculate CRL for VA role %s after CA reissue: %w", ski, err)
		lMessaging.Error(err)
		return err
	}

	return nil
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
