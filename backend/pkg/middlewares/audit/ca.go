package auditpub

import (
	"context"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/middlewares/eventpub"
	lservices "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

type CAAuditEventPublisher struct {
	next     services.CAService
	auditPub AuditPublisher
}

func NewCAAuditEventBusPublisher(audit AuditPublisher) lservices.CAMiddleware {
	return func(next services.CAService) services.CAService {
		return &CAAuditEventPublisher{
			next: next,
			auditPub: AuditPublisher{
				ICloudEventPublisher: eventpub.NewEventPublisherWithSourceMiddleware(audit, models.CASource),
			},
		}
	}
}

func (mw CAAuditEventPublisher) GetCryptoEngineProvider(ctx context.Context) ([]*models.CryptoEngineProvider, error) {
	return mw.next.GetCryptoEngineProvider(ctx)
}

func (mw CAAuditEventPublisher) GetStats(ctx context.Context) (*models.CAStats, error) {
	return mw.next.GetStats(ctx)
}
func (mw CAAuditEventPublisher) GetStatsByCAID(ctx context.Context, input services.GetStatsByCAIDInput) (map[models.CertificateStatus]int, error) {
	return mw.next.GetStatsByCAID(ctx, input)
}

func (mw CAAuditEventPublisher) CreateCA(ctx context.Context, input services.CreateCAInput) (output *models.CACertificate, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventCreateCAKey, input, err, output)
	}()

	return mw.next.CreateCA(ctx, input)
}

func (mw CAAuditEventPublisher) CreateHybridCA(ctx context.Context, input services.CreateHybridCAInput) (output *models.CACertificate, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventCreateHybridCAKey, input, err, output)
	}()

	return mw.next.CreateHybridCA(ctx, input)
}

func (mw CAAuditEventPublisher) RequestCACSR(ctx context.Context, input services.RequestCAInput) (output *models.CACertificateRequest, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventRequestCAKey, input, err, output)
	}()

	return mw.next.RequestCACSR(ctx, input)
}

func (mw CAAuditEventPublisher) ImportCA(ctx context.Context, input services.ImportCAInput) (output *models.CACertificate, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventImportCAKey, input, err, output)
	}()

	return mw.next.ImportCA(ctx, input)
}

func (mw CAAuditEventPublisher) GetCAByID(ctx context.Context, input services.GetCAByIDInput) (*models.CACertificate, error) {
	return mw.next.GetCAByID(ctx, input)
}

func (mw CAAuditEventPublisher) GetCAs(ctx context.Context, input services.GetCAsInput) (string, error) {
	return mw.next.GetCAs(ctx, input)
}

func (mw CAAuditEventPublisher) GetCAsByCommonName(ctx context.Context, input services.GetCAsByCommonNameInput) (string, error) {
	return mw.next.GetCAsByCommonName(ctx, input)
}

func (mw CAAuditEventPublisher) UpdateCAStatus(ctx context.Context, input services.UpdateCAStatusInput) (output *models.CACertificate, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventUpdateCAStatusKey, input, err, output)
	}()

	return mw.next.UpdateCAStatus(ctx, input)
}

func (mw CAAuditEventPublisher) UpdateCAProfile(ctx context.Context, input services.UpdateCAProfileInput) (output *models.CACertificate, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventUpdateCAProfileKey, input, err, output)
	}()

	return mw.next.UpdateCAProfile(ctx, input)
}

func (mw CAAuditEventPublisher) UpdateCAMetadata(ctx context.Context, input services.UpdateCAMetadataInput) (output *models.CACertificate, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventUpdateCAMetadataKey, input, err, output)
	}()

	return mw.next.UpdateCAMetadata(ctx, input)
}

func (mw CAAuditEventPublisher) DeleteCA(ctx context.Context, input services.DeleteCAInput) (err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventDeleteCAKey, input, err, map[string]any{})
	}()

	return mw.next.DeleteCA(ctx, input)
}

func (mw CAAuditEventPublisher) SignCertificate(ctx context.Context, input services.SignCertificateInput) (output *models.Certificate, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventSignCertificateKey, input, err, output)
	}()
	return mw.next.SignCertificate(ctx, input)
}

func (mw CAAuditEventPublisher) CreateCertificate(ctx context.Context, input services.CreateCertificateInput) (output *models.Certificate, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventCreateCertificateKey, input, err, output)
	}()

	return mw.next.CreateCertificate(ctx, input)
}

func (mw CAAuditEventPublisher) ImportCertificate(ctx context.Context, input services.ImportCertificateInput) (output *models.Certificate, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventImportCACertificateKey, input, err, output)
	}()

	return mw.next.ImportCertificate(ctx, input)
}

func (mw CAAuditEventPublisher) SignatureSign(ctx context.Context, input services.SignatureSignInput) (output []byte, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventSignatureSignKey, input, err, output)
	}()

	return mw.next.SignatureSign(ctx, input)
}

func (mw CAAuditEventPublisher) SignatureVerify(ctx context.Context, input services.SignatureVerifyInput) (output bool, err error) {
	return mw.next.SignatureVerify(ctx, input)
}

func (mw CAAuditEventPublisher) GetCertificateBySerialNumber(ctx context.Context, input services.GetCertificatesBySerialNumberInput) (*models.Certificate, error) {
	return mw.next.GetCertificateBySerialNumber(ctx, input)
}

func (mw CAAuditEventPublisher) GetCertificates(ctx context.Context, input services.GetCertificatesInput) (string, error) {
	return mw.next.GetCertificates(ctx, input)
}

func (mw CAAuditEventPublisher) GetCertificatesByCA(ctx context.Context, input services.GetCertificatesByCAInput) (string, error) {
	return mw.next.GetCertificatesByCA(ctx, input)
}

func (mw CAAuditEventPublisher) GetCertificatesByExpirationDate(ctx context.Context, input services.GetCertificatesByExpirationDateInput) (string, error) {
	return mw.next.GetCertificatesByExpirationDate(ctx, input)
}

func (mw CAAuditEventPublisher) UpdateCertificateStatus(ctx context.Context, input services.UpdateCertificateStatusInput) (output *models.Certificate, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventUpdateCertificateStatusKey, input, err, output)
	}()

	return mw.next.UpdateCertificateStatus(ctx, input)
}

func (mw CAAuditEventPublisher) GetCertificatesByCaAndStatus(ctx context.Context, input services.GetCertificatesByCaAndStatusInput) (string, error) {
	return mw.next.GetCertificatesByCaAndStatus(ctx, input)
}

func (mw CAAuditEventPublisher) GetCertificatesByStatus(ctx context.Context, input services.GetCertificatesByStatusInput) (string, error) {
	return mw.next.GetCertificatesByStatus(ctx, input)
}

func (mw CAAuditEventPublisher) UpdateCertificateMetadata(ctx context.Context, input services.UpdateCertificateMetadataInput) (output *models.Certificate, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventUpdateCertificateMetadataKey, input, err, output)
	}()

	return mw.next.UpdateCertificateMetadata(ctx, input)
}

func (mw CAAuditEventPublisher) DeleteCertificate(ctx context.Context, input services.DeleteCertificateInput) (err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventDeleteCertificateKey, input, err, nil)
	}()

	return mw.next.DeleteCertificate(ctx, input)
}

func (mw CAAuditEventPublisher) GetCARequestByID(ctx context.Context, input services.GetByIDInput) (*models.CACertificateRequest, error) {
	return mw.next.GetCARequestByID(ctx, input)
}

func (mw CAAuditEventPublisher) DeleteCARequestByID(ctx context.Context, input services.GetByIDInput) error {
	return mw.next.DeleteCARequestByID(ctx, input)
}

func (mw CAAuditEventPublisher) GetCARequests(ctx context.Context, input services.GetItemsInput[models.CACertificateRequest]) (string, error) {
	return mw.next.GetCARequests(ctx, input)
}

func (mw CAAuditEventPublisher) GetIssuanceProfiles(ctx context.Context, input services.GetIssuanceProfilesInput) (string, error) {
	return mw.next.GetIssuanceProfiles(ctx, input)
}

func (mw CAAuditEventPublisher) GetIssuanceProfileByID(ctx context.Context, input services.GetIssuanceProfileByIDInput) (*models.IssuanceProfile, error) {
	return mw.next.GetIssuanceProfileByID(ctx, input)
}

func (mw CAAuditEventPublisher) CreateIssuanceProfile(ctx context.Context, input services.CreateIssuanceProfileInput) (output *models.IssuanceProfile, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventCreateIssuanceProfileKey, input, err, output)
	}()

	return mw.next.CreateIssuanceProfile(ctx, input)
}

func (mw CAAuditEventPublisher) UpdateIssuanceProfile(ctx context.Context, input services.UpdateIssuanceProfileInput) (output *models.IssuanceProfile, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventUpdateIssuanceProfileKey, input, err, output)
	}()

	return mw.next.UpdateIssuanceProfile(ctx, input)
}

func (mw CAAuditEventPublisher) DeleteIssuanceProfile(ctx context.Context, input services.DeleteIssuanceProfileInput) (err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventDeleteIssuanceProfileKey, input, err, nil)
	}()

	return mw.next.DeleteIssuanceProfile(ctx, input)
}
