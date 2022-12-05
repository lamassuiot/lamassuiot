package postgres

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/common/api"
	dmserrors "github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/repository"
	"github.com/lamassuiot/lamassuiot/pkg/utils/common"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

type DeviceManufacturingServiceDAO struct {
	Name                      string `gorm:"primaryKey"`
	SerialNumber              string
	Status                    api.DMSStatus
	X509Asset                 string
	AuthorizedCAs             pq.StringArray `gorm:"type:text[]"`
	CreationTimestamp         pq.NullTime
	LastStatusUpdateTimestamp pq.NullTime
}

func (d *DeviceManufacturingServiceDAO) toDeviceManufacturingService() (api.DeviceManufacturingService, error) {
	var x509Asset api.X509Asset
	var x509AssetSubject pkix.Name

	decodedCert, err := base64.StdEncoding.DecodeString(d.X509Asset)
	if err != nil {
		return api.DeviceManufacturingService{}, errors.New("corrupted db: could not decode b64 x509 asset")
	}

	certBlock, _ := pem.Decode([]byte(decodedCert))
	if d.Status == api.DMSStatusPendingApproval || d.Status == api.DMSStatusRejected {
		certReq, err := x509.ParseCertificateRequest(certBlock.Bytes)
		if err != nil {
			return api.DeviceManufacturingService{}, errors.New("corrupted db: could not inflate certificate request")
		}

		x509AssetSubject = certReq.Subject

		x509Asset = api.X509Asset{
			IsCertificate:      false,
			Certificate:        nil,
			CertificateRequest: certReq,
		}
	} else {
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return api.DeviceManufacturingService{}, errors.New("corrupted db: could not inflate certificate")
		}

		x509AssetSubject = cert.Subject

		x509Asset = api.X509Asset{
			IsCertificate:      true,
			Certificate:        cert,
			CertificateRequest: nil,
		}
	}

	subject := api.Subject{
		CommonName: x509AssetSubject.CommonName,
	}

	if len(x509AssetSubject.Country) > 0 {
		subject.Country = x509AssetSubject.Country[0]
	}
	if len(x509AssetSubject.Organization) > 0 {
		subject.Organization = x509AssetSubject.Organization[0]
	}
	if len(x509AssetSubject.OrganizationalUnit) > 0 {
		subject.OrganizationUnit = x509AssetSubject.OrganizationalUnit[0]
	}
	if len(x509AssetSubject.Locality) > 0 {
		subject.Locality = x509AssetSubject.Locality[0]
	}
	if len(x509AssetSubject.Province) > 0 {
		subject.State = x509AssetSubject.Province[0]
	}

	authorizedCAs := make([]string, 0)
	if len(d.AuthorizedCAs) > 0 {
		authorizedCAs = d.AuthorizedCAs
	}

	return api.DeviceManufacturingService{
		Name:                      d.Name,
		Status:                    d.Status,
		SerialNumber:              d.SerialNumber,
		X509Asset:                 x509Asset,
		Subject:                   subject,
		AuthorizedCAs:             authorizedCAs,
		CreationTimestamp:         d.CreationTimestamp,
		LastStatusUpdateTimestamp: d.LastStatusUpdateTimestamp,
	}, nil
}

func (DeviceManufacturingServiceDAO) TableName() string {
	return "dms"
}

func NewPostgresDB(db *gorm.DB) repository.DeviceManufacturingServiceRepository {
	db.AutoMigrate(&DeviceManufacturingServiceDAO{})

	return &PostgresDBContext{db}
}

type PostgresDBContext struct {
	*gorm.DB
}

func (db *PostgresDBContext) Insert(ctx context.Context, csr *x509.CertificateRequest) error {
	now := time.Now()

	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
	certificateEnc := make([]byte, base64.StdEncoding.EncodedLen(len(pemCert)))
	base64.StdEncoding.Encode(certificateEnc, pemCert)

	dms := DeviceManufacturingServiceDAO{
		Name:                      csr.Subject.CommonName,
		Status:                    api.DMSStatusPendingApproval,
		AuthorizedCAs:             []string{},
		CreationTimestamp:         pq.NullTime{Valid: true, Time: now},
		LastStatusUpdateTimestamp: pq.NullTime{Valid: true, Time: now},
		X509Asset:                 string(certificateEnc),
	}

	if err := db.WithContext(ctx).Model(&DeviceManufacturingServiceDAO{}).Create(&dms).Error; err != nil {
		duplicationErr := &dmserrors.DuplicateResourceError{
			ResourceType: "DMS",
			ResourceId:   dms.Name,
		}
		return duplicationErr
	}

	return nil
}

func (db *PostgresDBContext) SelectByName(ctx context.Context, name string) (api.DeviceManufacturingService, error) {
	var dms DeviceManufacturingServiceDAO
	if err := db.WithContext(ctx).Model(&DeviceManufacturingServiceDAO{}).Where("name = ?", name).First(&dms).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			notFoundErr := &dmserrors.ResourceNotFoundError{
				ResourceType: "DMS",
				ResourceId:   name,
			}
			return api.DeviceManufacturingService{}, notFoundErr
		} else {
			return api.DeviceManufacturingService{}, err
		}
	}
	return dms.toDeviceManufacturingService()
}

func (db *PostgresDBContext) SelectAll(ctx context.Context, queryParameters common.QueryParameters) (int, []api.DeviceManufacturingService, error) {
	var totalDMSs int64
	if err := db.WithContext(ctx).Model(&DeviceManufacturingServiceDAO{}).Count(&totalDMSs).Error; err != nil {
		return 0, []api.DeviceManufacturingService{}, err
	}

	var dmss []DeviceManufacturingServiceDAO
	tx := db.WithContext(ctx).Model(&DeviceManufacturingServiceDAO{})
	tx = filters.ApplyQueryParametersFilters(tx, queryParameters)
	if err := tx.Find(&dmss).Error; err != nil {
		return 0, []api.DeviceManufacturingService{}, err
	}

	var parsedDMSs []api.DeviceManufacturingService
	for _, v := range dmss {
		dms, err := v.toDeviceManufacturingService()
		if err != nil {
			continue
		}
		parsedDMSs = append(parsedDMSs, dms)
	}

	return int(totalDMSs), parsedDMSs, nil
}

func (db *PostgresDBContext) UpdateStatus(ctx context.Context, name string, status api.DMSStatus) error {
	var dms DeviceManufacturingServiceDAO
	if err := db.WithContext(ctx).Model(&DeviceManufacturingServiceDAO{}).Where("name = ?", name).First(&dms).Error; err != nil {
		return err
	}

	dms.Status = status
	dms.LastStatusUpdateTimestamp = pq.NullTime{Valid: true, Time: time.Now()}

	if err := db.Save(&dms).Error; err != nil {
		return err
	}
	return nil
}

func (db *PostgresDBContext) UpdateAuthorizedCAs(ctx context.Context, name string, authorizedCAs []string) error {
	var dms DeviceManufacturingServiceDAO
	if err := db.WithContext(ctx).Model(&DeviceManufacturingServiceDAO{}).Where("name = ?", name).First(&dms).Error; err != nil {
		return err
	}

	dms.AuthorizedCAs = authorizedCAs
	dms.LastStatusUpdateTimestamp = pq.NullTime{Valid: true, Time: time.Now()}

	if err := db.Save(&dms).Error; err != nil {
		return err
	}

	return nil
}

func (db *PostgresDBContext) UpdateDMS(ctx context.Context, dms api.DeviceManufacturingService) error {
	var dmsToUpdate DeviceManufacturingServiceDAO
	if err := db.WithContext(ctx).Model(&DeviceManufacturingServiceDAO{}).Where("name = ?", dms.Name).First(&dmsToUpdate).Error; err != nil {
		return err
	}

	newUpdateTimestamp := dms.LastStatusUpdateTimestamp
	if dmsToUpdate.Status != dms.Status {
		newUpdateTimestamp = pq.NullTime{Valid: true, Time: time.Now()}
	}

	asset := ""
	var pemBytes []byte
	if dms.X509Asset.IsCertificate {
		if dms.X509Asset.Certificate != nil {
			pemBytes = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: dms.X509Asset.Certificate.Raw})
		}
	} else {
		if dms.X509Asset.CertificateRequest != nil {
			pemBytes = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: dms.X509Asset.CertificateRequest.Raw})
		}
	}
	pemEncoded := base64.StdEncoding.EncodeToString(pemBytes)
	asset = string(pemEncoded)

	dmsToUpdate = DeviceManufacturingServiceDAO{
		Name:                      dms.Name,
		Status:                    dms.Status,
		SerialNumber:              dms.SerialNumber,
		AuthorizedCAs:             dms.AuthorizedCAs,
		CreationTimestamp:         dms.CreationTimestamp,
		LastStatusUpdateTimestamp: newUpdateTimestamp,
		X509Asset:                 asset,
	}

	if err := db.Save(&dmsToUpdate).Error; err != nil {
		return err
	}

	return nil
}
