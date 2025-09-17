package eventpub

import (
	"context"
	"fmt"

	lservices "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

type CAEventPublisher struct {
	Next       services.CAService
	eventMWPub ICloudEventPublisher
}

func NewCAEventBusPublisher(eventMWPub ICloudEventPublisher) lservices.CAMiddleware {
	return func(next services.CAService) services.CAService {
		return &CAEventPublisher{
			Next:       next,
			eventMWPub: NewEventPublisherWithSourceMiddleware(eventMWPub, models.CASource),
		}
	}
}

func (mw CAEventPublisher) GetCryptoEngineProvider(ctx context.Context) ([]*models.CryptoEngineProvider, error) {
	return mw.Next.GetCryptoEngineProvider(ctx)
}

func (mw CAEventPublisher) GetStats(ctx context.Context) (*models.CAStats, error) {
	return mw.Next.GetStats(ctx)
}
func (mw CAEventPublisher) GetStatsByCAID(ctx context.Context, input services.GetStatsByCAIDInput) (map[models.CertificateStatus]int, error) {
	return mw.Next.GetStatsByCAID(ctx, input)
}

func (mw CAEventPublisher) CreateCA(ctx context.Context, input services.CreateCAInput) (output *models.CACertificate, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventCreateCAKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("ca/%s", input.ID))

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, output)
		}
	}()
	return mw.Next.CreateCA(ctx, input)
}

func (mw CAEventPublisher) RequestCACSR(ctx context.Context, input services.RequestCAInput) (output *models.CACertificateRequest, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventRequestCAKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("ca-csr/%s", input.ID))

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, output)
		}
	}()
	return mw.Next.RequestCACSR(ctx, input)
}

func (mw CAEventPublisher) ImportCA(ctx context.Context, input services.ImportCAInput) (output *models.CACertificate, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventImportCAKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("ca/%s", input.ID))

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, output)
		}
	}()
	return mw.Next.ImportCA(ctx, input)
}

func (mw CAEventPublisher) GetCAByID(ctx context.Context, input services.GetCAByIDInput) (*models.CACertificate, error) {
	return mw.Next.GetCAByID(ctx, input)
}

func (mw CAEventPublisher) GetCAs(ctx context.Context, input services.GetCAsInput) (string, error) {
	return mw.Next.GetCAs(ctx, input)
}

func (mw CAEventPublisher) GetCAsByCommonName(ctx context.Context, input services.GetCAsByCommonNameInput) (string, error) {
	return mw.Next.GetCAsByCommonName(ctx, input)
}

func (mw CAEventPublisher) UpdateCAStatus(ctx context.Context, input services.UpdateCAStatusInput) (output *models.CACertificate, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventUpdateCAStatusKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("ca/%s", input.CAID))

	prev, err := mw.GetCAByID(ctx, services.GetCAByIDInput{
		CAID: input.CAID,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get CA %s: %w", input.CAID, err)
	}

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, models.UpdateModel[models.CACertificate]{
				Updated:  *output,
				Previous: *prev,
			})
		}
	}()
	return mw.Next.UpdateCAStatus(ctx, input)
}

func (mw CAEventPublisher) UpdateCAProfile(ctx context.Context, input services.UpdateCAProfileInput) (output *models.CACertificate, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventUpdateCAProfileKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("ca/%s", input.CAID))

	prev, err := mw.GetCAByID(ctx, services.GetCAByIDInput{
		CAID: input.CAID,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get CA %s: %w", input.CAID, err)
	}

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, models.UpdateModel[models.CACertificate]{
				Updated:  *output,
				Previous: *prev,
			})
		}
	}()

	return mw.Next.UpdateCAProfile(ctx, input)
}

func (mw CAEventPublisher) UpdateCAMetadata(ctx context.Context, input services.UpdateCAMetadataInput) (output *models.CACertificate, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventUpdateCAMetadataKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("ca/%s", input.CAID))

	prev, err := mw.GetCAByID(ctx, services.GetCAByIDInput{
		CAID: input.CAID,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get CA %s: %w", input.CAID, err)
	}

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, models.UpdateModel[models.CACertificate]{
				Updated:  *output,
				Previous: *prev,
			})
		}
	}()
	return mw.Next.UpdateCAMetadata(ctx, input)
}

func (mw CAEventPublisher) DeleteCA(ctx context.Context, input services.DeleteCAInput) (err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventDeleteCAKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("ca/%s", input.CAID))

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, input)
		}
	}()
	return mw.Next.DeleteCA(ctx, input)
}

func (mw CAEventPublisher) SignCertificate(ctx context.Context, input services.SignCertificateInput) (output *models.Certificate, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventSignCertificateKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("ca/%s", input.CAID)) //@jjrodrig is this a CA entitiy or Certificate entity?

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, output)
		}
	}()
	return mw.Next.SignCertificate(ctx, input)
}

func (mw CAEventPublisher) CreateCertificate(ctx context.Context, input services.CreateCertificateInput) (output *models.Certificate, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventCreateCertificateKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("certificate/%s", input.Subject.CommonName)) //@jjrodrig dont know if this ID is correct

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, output)
		}
	}()
	return mw.Next.CreateCertificate(ctx, input)
}

func (mw CAEventPublisher) ImportCertificate(ctx context.Context, input services.ImportCertificateInput) (output *models.Certificate, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventImportCertificateKey)
	serialNumber := ""
	if input.Certificate != nil && input.Certificate.SerialNumber != nil {
		serialNumber = input.Certificate.SerialNumber.String()
	}
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("certificate/%s", serialNumber))

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, output)
		}
	}()
	return mw.Next.ImportCertificate(ctx, input)
}

func (mw CAEventPublisher) SignatureSign(ctx context.Context, input services.SignatureSignInput) (output []byte, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventSignatureSignKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("ca/%s", input.CAID))

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, output)
		}
	}()
	return mw.Next.SignatureSign(ctx, input)
}

func (mw CAEventPublisher) SignatureVerify(ctx context.Context, input services.SignatureVerifyInput) (output bool, err error) {
	return mw.Next.SignatureVerify(ctx, input)
}

func (mw CAEventPublisher) GetCertificateBySerialNumber(ctx context.Context, input services.GetCertificatesBySerialNumberInput) (*models.Certificate, error) {
	return mw.Next.GetCertificateBySerialNumber(ctx, input)
}

func (mw CAEventPublisher) GetCertificates(ctx context.Context, input services.GetCertificatesInput) (string, error) {
	return mw.Next.GetCertificates(ctx, input)
}

func (mw CAEventPublisher) GetCertificatesByCA(ctx context.Context, input services.GetCertificatesByCAInput) (string, error) {
	return mw.Next.GetCertificatesByCA(ctx, input)
}

func (mw CAEventPublisher) GetCertificatesByExpirationDate(ctx context.Context, input services.GetCertificatesByExpirationDateInput) (string, error) {
	return mw.Next.GetCertificatesByExpirationDate(ctx, input)
}

func (mw CAEventPublisher) UpdateCertificateStatus(ctx context.Context, input services.UpdateCertificateStatusInput) (output *models.Certificate, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventUpdateCertificateStatusKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("certificate/%s", input.SerialNumber))

	prev, err := mw.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{
		SerialNumber: input.SerialNumber,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get Certificate %s: %w", input.SerialNumber, err)
	}

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, models.UpdateModel[models.Certificate]{
				Previous: *prev,
				Updated:  *output,
			})
		}
	}()
	return mw.Next.UpdateCertificateStatus(ctx, input)
}

func (mw CAEventPublisher) GetCertificatesByCaAndStatus(ctx context.Context, input services.GetCertificatesByCaAndStatusInput) (string, error) {
	return mw.Next.GetCertificatesByCaAndStatus(ctx, input)
}

func (mw CAEventPublisher) GetCertificatesByStatus(ctx context.Context, input services.GetCertificatesByStatusInput) (string, error) {
	return mw.Next.GetCertificatesByStatus(ctx, input)
}

func (mw CAEventPublisher) UpdateCertificateMetadata(ctx context.Context, input services.UpdateCertificateMetadataInput) (output *models.Certificate, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventUpdateCertificateMetadataKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("certificate/%s", input.SerialNumber))

	prev, err := mw.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{
		SerialNumber: input.SerialNumber,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get Certificate %s: %w", input.SerialNumber, err)
	}

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, models.UpdateModel[models.Certificate]{
				Previous: *prev,
				Updated:  *output,
			})
		}
	}()
	return mw.Next.UpdateCertificateMetadata(ctx, input)
}

func (mw CAEventPublisher) DeleteCertificate(ctx context.Context, input services.DeleteCertificateInput) (err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventDeleteCertificateKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("certificate/%s", input.SerialNumber))

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, input)
		}
	}()
	return mw.Next.DeleteCertificate(ctx, input)
}

func (mw CAEventPublisher) GetCARequestByID(ctx context.Context, input services.GetByIDInput) (*models.CACertificateRequest, error) {
	return mw.Next.GetCARequestByID(ctx, input)
}

func (mw CAEventPublisher) DeleteCARequestByID(ctx context.Context, input services.GetByIDInput) error {
	return mw.Next.DeleteCARequestByID(ctx, input)
}

func (mw CAEventPublisher) GetCARequests(ctx context.Context, input services.GetItemsInput[models.CACertificateRequest]) (string, error) {
	return mw.Next.GetCARequests(ctx, input)
}

func (mw CAEventPublisher) GetIssuanceProfiles(ctx context.Context, input services.GetIssuanceProfilesInput) (string, error) {
	return mw.Next.GetIssuanceProfiles(ctx, input)
}

func (mw CAEventPublisher) GetIssuanceProfileByID(ctx context.Context, input services.GetIssuanceProfileByIDInput) (*models.IssuanceProfile, error) {
	return mw.Next.GetIssuanceProfileByID(ctx, input)
}

func (mw CAEventPublisher) CreateIssuanceProfile(ctx context.Context, input services.CreateIssuanceProfileInput) (output *models.IssuanceProfile, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventCreateIssuanceProfileKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, "profile/unknown")

	defer func() {
		ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("profile/%s", output.ID))
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, output)
		}
	}()
	return mw.Next.CreateIssuanceProfile(ctx, input)

}

func (mw CAEventPublisher) UpdateIssuanceProfile(ctx context.Context, input services.UpdateIssuanceProfileInput) (output *models.IssuanceProfile, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventUpdateIssuanceProfileKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("profile/%s", input.Profile.ID))

	prev, err := mw.GetIssuanceProfileByID(ctx, services.GetIssuanceProfileByIDInput{
		ProfileID: input.Profile.ID,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get IssuanceProfile %s: %w", input.Profile.ID, err)
	}

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, models.UpdateModel[models.IssuanceProfile]{
				Previous: *prev,
				Updated:  *output,
			})
		}
	}()
	return mw.Next.UpdateIssuanceProfile(ctx, input)

}

func (mw CAEventPublisher) DeleteIssuanceProfile(ctx context.Context, input services.DeleteIssuanceProfileInput) (err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventDeleteIssuanceProfileKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("profile/%s", input.ProfileID))
	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, input)
		}
	}()
	return mw.Next.DeleteIssuanceProfile(ctx, input)
}
