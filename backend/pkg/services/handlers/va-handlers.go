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
			string(models.EventCreateCAKey): func(ctx context.Context, m *event.Event) error { return createCAHandler(ctx, m, svc, l) },
			// An imported CA raises ca.import instead of ca.create, and it also needs its CRL settings: the ones
			// imported with a key in the KMS can sign CRLs. InitCRLSettings leaves the keyless ones without settings.
			string(models.EventImportCAKey):                func(ctx context.Context, m *event.Event) error { return createCAHandler(ctx, m, svc, l) },
			string(models.EventReissueCAKey):               func(ctx context.Context, m *event.Event) error { return reissueCAHandler(ctx, m, svc, l) },
			string(models.EventUpdateCertificateStatusKey): func(ctx context.Context, m *event.Event) error { return updateCertificateStatus(ctx, m, svc, l) },
			string(models.EventUpdateCAStatusKey):          func(ctx context.Context, m *event.Event) error { return updateCAStatusHandler(ctx, m, svc, l) },
			string(models.EventDeleteCAKey):                func(ctx context.Context, m *event.Event) error { return deleteCAHandler(ctx, m, svc, l) },
		},
	}
}

// reissueCAHandler moves the CRL signer of the CRL settings of the CA to its reissued certificate, then regenerates the
// CRL so it is signed by that certificate right away. Only settings signed by the CA certificate being superseded are
// updated: any other signer was chosen on purpose and is kept.
func reissueCAHandler(ctx context.Context, event *event.Event, crlSvc services.CRLService, lMessaging *logrus.Entry) error {
	ca, err := helpers.GetEventBody[models.UpdateModel[models.CACertificate]](event)
	if err != nil {
		err = fmt.Errorf("could not decode cloud event: %s", err)
		lMessaging.Error(err)
		return err
	}

	caID := ca.Updated.ID
	prevSN := ca.Previous.Certificate.SerialNumber
	newSN := ca.Updated.Certificate.SerialNumber

	settings, err := crlSvc.GetCRLSettings(ctx, services.GetCRLSettingsInput{CAID: caID})
	if errors.Is(err, errs.ErrCRLSettingsNotFound) {
		lMessaging.Warnf("reissued CA %s has no CRL settings: no CRL signer to update", caID)
		return nil
	}
	if err != nil {
		err = fmt.Errorf("could not get CRL settings for reissued CA %s: %w", caID, err)
		lMessaging.Error(err)
		return err
	}

	if settings.Status != models.CRLSettingsActive {
		lMessaging.Infof("CRL settings of CA %s are %s: ignoring its reissue", caID, settings.Status)
		return nil
	}

	switch settings.Options.SignerSerialNumber {
	case newSN:
		// A retry of this event after a failed CRL generation: the signer is already moved, only the CRL is missing.
		lMessaging.Infof("CRL settings of CA %s signer is already the reissued certificate %s", caID, newSN)
	case prevSN:
		options := settings.Options
		options.SignerSerialNumber = newSN
		_, err = crlSvc.UpdateCRLSettings(ctx, services.UpdateCRLSettingsInput{
			CAID:    caID,
			Options: options,
		})
		if errors.Is(err, errs.ErrValidateBadRequest) {
			lMessaging.Warnf("reissued certificate %s of CA %s cannot sign CRLs (it needs the cRLSign key usage): CRL settings keep signer %s", newSN, caID, prevSN)
			return nil
		}
		if err != nil {
			err = fmt.Errorf("could not update CRL signer of CA %s to certificate %s: %w", caID, newSN, err)
			lMessaging.Error(err)
			return err
		}

		lMessaging.Infof("CRL signer of CA %s moved from certificate %s to reissued certificate %s", caID, prevSN, newSN)
	default:
		lMessaging.Infof("CRL settings of CA %s are signed by certificate %s, not by the superseded certificate %s: keeping its CRL signer", caID, settings.Options.SignerSerialNumber, prevSN)
		return nil
	}

	_, err = crlSvc.CalculateCRL(ctx, services.CalculateCRLInput{CAID: caID})
	if err != nil {
		err = fmt.Errorf("could not calculate CRL for CA %s after its reissue: %w", caID, err)
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

	settings, err := crlSvc.InitCRLSettings(ctx, ca.ID)

	if err != nil {
		err = fmt.Errorf("could not initialize CRL settings: %s", err)
		lMessaging.Error(err)
		return err
	}

	if settings == nil {
		lMessaging.Infof("CA %s has no key to sign CRLs: no CRL settings created", ca.ID)
		return nil
	}

	lMessaging.Infof("CRL settings initialized for CA %s", ca.ID)

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
	// The CRL is the one of the CA that issued the certificate. CAs sharing a key share the AKI, so it cannot tell them apart.
	issuerID := cert.Updated.IssuerCAMetadata.ID

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

		lMessaging.Infof("Certificate %s %s - %s (CA %s) is being processed for CRL update due to %s", cn, ski, icn, issuerID, action)

		settings, err := crlSvc.GetCRLSettings(ctx, services.GetCRLSettingsInput{
			CAID: issuerID,
		})
		if errors.Is(err, errs.ErrCRLSettingsNotFound) {
			// No settings means no CRL is published yet. If they are created later, their first CRL is built from the
			// CA's revoked certificates and already includes this one, so retrying would only hold
			// back every later certificate event.
			lMessaging.Warnf("issuer CA %s has no CRL settings: no CRL to regenerate for certificate %s %s", issuerID, cn, ski)
			return nil
		}
		if err != nil {
			err = fmt.Errorf("could not get CRL settings for certificate %s %s - %s (CA %s): %s", cn, ski, icn, issuerID, err)
			lMessaging.Error(err)
			return err
		}

		if settings.Status != models.CRLSettingsActive {
			lMessaging.Infof("CRL settings of CA %s are %s: not regenerating its CRL", issuerID, settings.Status)
			return nil
		}

		if settings.Options.RegenerateOnRevoke {
			_, err = crlSvc.CalculateCRL(ctx, services.CalculateCRLInput{
				CAID: issuerID,
			})
			if err != nil {
				err = fmt.Errorf("could not calculate CRL for certificate %s %s - %s (CA %s): %s", cn, ski, icn, issuerID, err)
				lMessaging.Error(err)
				return err
			}
			lMessaging.Infof("CRL regenerated for CA %s due to certificate %s", issuerID, action)
		} else {
			lMessaging.Infof("CRL regeneration disabled for CA %s, skipping CRL update", issuerID)
		}
	}

	return nil
}

// updateCAStatusHandler moves the CRL settings of the CA to the status its CA calls for (a revoked CA gets its final
// CRL), then regenerates the CRL of the CA that issued it: UpdateCAStatus publishes no certificate.status.update for the
// certificate of the CA itself, so its revocation would otherwise wait for the next refresh of that CRL.
func updateCAStatusHandler(ctx context.Context, event *event.Event, crlSvc services.CRLService, lMessaging *logrus.Entry) error {
	ca, err := helpers.GetEventBody[models.UpdateModel[models.CACertificate]](event)
	if err != nil {
		err = fmt.Errorf("could not decode cloud event: %s", err)
		lMessaging.Error(err)
		return err
	}

	caID := ca.Updated.ID
	// The CA is read again rather than taken from the event, which may be stale or redelivered.
	settings, err := crlSvc.ReconcileCRLSettings(ctx, services.ReconcileCRLSettingsInput{CAID: caID})
	switch {
	case errors.Is(err, errs.ErrCRLSettingsNotFound):
		lMessaging.Infof("CA %s has no CRL settings: nothing to update for its status %s", caID, ca.Updated.Certificate.Status)
	case err != nil:
		err = fmt.Errorf("could not update the CRL settings of CA %s to its status %s: %w", caID, ca.Updated.Certificate.Status, err)
		lMessaging.Error(err)
		return err
	default:
		lMessaging.Infof("CRL settings of CA %s are %s after its status changed to %s", caID, settings.Status, ca.Updated.Certificate.Status)
	}

	return regenerateIssuerCRL(ctx, ca, crlSvc, lMessaging)
}

// regenerateIssuerCRL regenerates the CRL of the issuer of a CA that was revoked (for any reason) or reactivated from
// hold, as updateCertificateStatus does for the certificates it issued.
func regenerateIssuerCRL(ctx context.Context, ca *models.UpdateModel[models.CACertificate], crlSvc services.CRLService, lMessaging *logrus.Entry) error {
	updated, previous := ca.Updated.Certificate, ca.Previous.Certificate
	issuerID := updated.IssuerCAMetadata.ID
	reactivated := previous.Status == models.StatusRevoked && previous.RevocationReason == ocsp.CertificateHold && updated.Status == models.StatusActive
	if issuerID == "" || issuerID == ca.Updated.ID || (updated.Status != models.StatusRevoked && !reactivated) {
		return nil
	}

	issuer, err := crlSvc.GetCRLSettings(ctx, services.GetCRLSettingsInput{CAID: issuerID})
	if errors.Is(err, errs.ErrCRLSettingsNotFound) {
		lMessaging.Infof("issuer CA %s of CA %s has no CRL settings: no CRL to regenerate", issuerID, ca.Updated.ID)
		return nil
	}
	if err != nil {
		err = fmt.Errorf("could not get CRL settings of issuer CA %s of CA %s: %w", issuerID, ca.Updated.ID, err)
		lMessaging.Error(err)
		return err
	}
	if issuer.Status != models.CRLSettingsActive || !issuer.Options.RegenerateOnRevoke {
		lMessaging.Infof("CRL of issuer CA %s is not regenerated for CA %s: settings %s, regenerate on revoke %t", issuerID, ca.Updated.ID, issuer.Status, issuer.Options.RegenerateOnRevoke)
		return nil
	}

	if _, err := crlSvc.CalculateCRL(ctx, services.CalculateCRLInput{CAID: issuerID}); err != nil {
		err = fmt.Errorf("could not regenerate the CRL of issuer CA %s for CA %s: %w", issuerID, ca.Updated.ID, err)
		lMessaging.Error(err)
		return err
	}
	lMessaging.Infof("CRL of issuer CA %s regenerated for the status %s of CA %s", issuerID, updated.Status, ca.Updated.ID)
	return nil
}

// deleteCAHandler archives the CRL settings of a deleted CA: its last CRL is still served, and its signer certificate
// is no longer retained. It reconciles them rather than archiving them outright: the CA is checked to be gone, not
// taken from the event.
func deleteCAHandler(ctx context.Context, event *event.Event, crlSvc services.CRLService, lMessaging *logrus.Entry) error {
	input, err := helpers.GetEventBody[services.DeleteCAInput](event)
	if err != nil {
		err = fmt.Errorf("could not decode cloud event: %s", err)
		lMessaging.Error(err)
		return err
	}

	_, err = crlSvc.ReconcileCRLSettings(ctx, services.ReconcileCRLSettingsInput{CAID: input.CAID})
	if errors.Is(err, errs.ErrCRLSettingsNotFound) {
		lMessaging.Infof("deleted CA %s has no CRL settings to archive", input.CAID)
		return nil
	}
	if err != nil {
		err = fmt.Errorf("could not archive the CRL settings of deleted CA %s: %w", input.CAID, err)
		lMessaging.Error(err)
		return err
	}

	lMessaging.Infof("CRL settings of deleted CA %s reconciled", input.CAID)
	return nil
}
