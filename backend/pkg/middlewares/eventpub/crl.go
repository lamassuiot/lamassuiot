package eventpub

import (
	"context"
	"crypto/x509"
	"fmt"

	beService "github.com/lamassuiot/lamassuiot/v4/backend/pkg/services"
	"github.com/lamassuiot/lamassuiot/v4/core"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
)

type clrEventPublisher struct {
	next       services.CRLService
	eventMWPub ICloudEventPublisher
}

func NewCRLEventPublisher(eventMWPub ICloudEventPublisher) beService.CRLMiddleware {
	return func(next services.CRLService) services.CRLService {
		return &clrEventPublisher{
			next:       next,
			eventMWPub: NewEventPublisherWithSourceMiddleware(eventMWPub, models.VASource),
		}
	}
}

func (mw *clrEventPublisher) GetCRL(ctx context.Context, input services.GetCRLInput) (output *x509.RevocationList, err error) {
	return mw.next.GetCRL(ctx, input)
}

func (mw *clrEventPublisher) GetCRLSettings(ctx context.Context, input services.GetCRLSettingsInput) (output *models.CRLSettings, err error) {
	return mw.next.GetCRLSettings(ctx, input)
}

func (mw *clrEventPublisher) GetCRLSettingsList(ctx context.Context, input services.GetCRLSettingsListInput) (string, error) {
	return mw.next.GetCRLSettingsList(ctx, input)
}

func (mw *clrEventPublisher) UpdateCRLSettings(ctx context.Context, input services.UpdateCRLSettingsInput) (output *models.CRLSettings, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventUpdateCRLSettings)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("crl/%s", input.CAID))

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, output)
		}
	}()
	return mw.next.UpdateCRLSettings(ctx, input)
}

func (mw *clrEventPublisher) CalculateCRL(ctx context.Context, input services.CalculateCRLInput) (output *x509.RevocationList, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventCreateCRL)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("crl/%s", input.CAID))

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, output)
		}
	}()
	return mw.next.CalculateCRL(ctx, input)
}

func (mw *clrEventPublisher) InitCRLSettings(ctx context.Context, caID string) (output *models.CRLSettings, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventInitCRLSettings)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("crl/%s", caID))

	defer func() {
		// No settings (a CA without a key) means nothing to announce.
		if err == nil && output != nil {
			mw.eventMWPub.PublishCloudEvent(ctx, output)
		}
	}()
	return mw.next.InitCRLSettings(ctx, caID)
}

func (mw *clrEventPublisher) FinalizeCRLSettings(ctx context.Context, input services.FinalizeCRLSettingsInput) (output *models.CRLSettings, err error) {
	// The final CRL is only issued by this call if the settings were still ACTIVE: finalizing FINAL settings again, as a
	// retried event does, issues none.
	issuesFinalCRL := false
	if input.FinalCRL {
		if before, getErr := mw.next.GetCRLSettings(ctx, services.GetCRLSettingsInput{CAID: input.CAID}); getErr == nil {
			issuesFinalCRL = before.Status == models.CRLSettingsActive
		}
	}

	finalizeCtx := context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventFinalizeCRLSettings)
	finalizeCtx = context.WithValue(finalizeCtx, core.LamassuContextKeyEventSubject, fmt.Sprintf("crl/%s", input.CAID))

	defer func() {
		if err != nil {
			return
		}
		// The final CRL is a CRL publication like any other, announced as such before the settings change.
		if issuesFinalCRL && output != nil && output.Status == models.CRLSettingsFinal && output.LatestCRL.Version.Int != nil {
			crl, getErr := mw.next.GetCRL(ctx, services.GetCRLInput{ID: input.CAID, CRLVersion: output.LatestCRL.Version.Int})
			if getErr == nil {
				createCtx := context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventCreateCRL)
				createCtx = context.WithValue(createCtx, core.LamassuContextKeyEventSubject, fmt.Sprintf("crl/%s", input.CAID))
				mw.eventMWPub.PublishCloudEvent(createCtx, crl)
			}
		}
		mw.eventMWPub.PublishCloudEvent(finalizeCtx, output)
	}()
	return mw.next.FinalizeCRLSettings(finalizeCtx, input)
}

func (mw *clrEventPublisher) ArchiveCRLSettings(ctx context.Context, input services.ArchiveCRLSettingsInput) (output *models.CRLSettings, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventArchiveCRLSettings)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("crl/%s", input.CAID))

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, output)
		}
	}()
	return mw.next.ArchiveCRLSettings(ctx, input)
}

func (mw *clrEventPublisher) DeleteCRLSettings(ctx context.Context, input services.DeleteCRLSettingsInput) (err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventDeleteCRLSettings)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("crl/%s", input.CAID))

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, input)
		}
	}()
	return mw.next.DeleteCRLSettings(ctx, input)
}

// ReconcileCRLSettings publishes no event of its own: the changes it makes go through FinalizeCRLSettings and
// ArchiveCRLSettings, which publish theirs.
func (mw *clrEventPublisher) ReconcileCRLSettings(ctx context.Context, input services.ReconcileCRLSettingsInput) (*models.CRLSettings, error) {
	return mw.next.ReconcileCRLSettings(ctx, input)
}
