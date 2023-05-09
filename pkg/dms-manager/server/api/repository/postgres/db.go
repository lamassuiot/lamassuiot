package postgres

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
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
	Name                 string `gorm:"primaryKey"`
	Status               api.DMSStatus
	IsCloudDMS           bool
	CreationTimestamp    time.Time
	IdentityProfile      IdentityProfileDAO      `gorm:"foreignKey:DMSName"`
	RemoteAccessIdentity RemoteAccessIdentityDAO `gorm:"foreignKey:DMSName"`
}

type RemoteAccessIdentityDAO struct {
	DMSName               string `gorm:"primaryKey"`
	ExternalKeyGeneration bool
	AuthorizedCAs         pq.StringArray `gorm:"type:text[]"`
	SerialNumber          string
	Certificate           string
	CertificateRequest    string
}

type IdentityProfileDAO struct {
	DMSName                    string `gorm:"primaryKey"`
	EnrollmentMode             string
	AuthenticationMode         string
	BootstrapCAs               pq.StringArray `gorm:"type:text[]"`
	AuthorizedCA               string
	Icon                       string
	Color                      string
	Tags                       pq.StringArray `gorm:"type:text[]"`
	PreventiveRenewalInterval  string
	IncludeAuthorizedCA        bool
	IncludeBootstrapCAs        bool
	IncludeLamassuDownstreamCA bool
	ManagedCAs                 pq.StringArray `gorm:"type:text[]"`
	StaticCAs                  []StaticCADAO  `gorm:"foreignKey:DMSName;References:DMSName"`
	PublishToAWS               bool
}

type StaticCADAO struct {
	DMSName     string `gorm:"primaryKey"`
	ID          string `gorm:"primaryKey"`
	Certificate string
}

func (d *RemoteAccessIdentityDAO) toRemoteAccessIdentity() *api.RemoteAccessIdentity {
	rai := api.RemoteAccessIdentity{
		ExternalKeyGeneration:    d.ExternalKeyGeneration,
		AuthorizedCAs:            d.AuthorizedCAs,
		SerialNumber:             d.SerialNumber,
		CertificateString:        d.Certificate,
		CertificateRequestString: d.CertificateRequest,
	}

	if rai.CertificateString != "" {
		decodedBytes, err := base64.StdEncoding.DecodeString(rai.CertificateString)
		if err == nil {
			certBlock, _ := pem.Decode([]byte(decodedBytes))
			cert, _ := x509.ParseCertificate(certBlock.Bytes)
			rai.Certificate = cert
		}
	}

	if rai.CertificateRequestString != "" {
		decodedBytes, err := base64.StdEncoding.DecodeString(rai.CertificateRequestString)
		if err == nil {
			certBlock, _ := pem.Decode([]byte(decodedBytes))
			csr, _ := x509.ParseCertificateRequest(certBlock.Bytes)
			rai.CertificateRequest = csr
		}
	}

	if rai.Certificate != nil {
		rai.Subject = api.Subject{
			CommonName:       rai.Certificate.Subject.CommonName,
			Organization:     strings.Join(rai.Certificate.Subject.Organization, ","),
			OrganizationUnit: strings.Join(rai.Certificate.Subject.OrganizationalUnit, ","),
			Country:          strings.Join(rai.Certificate.Subject.Country, ","),
			State:            strings.Join(rai.Certificate.Subject.Province, ","),
			Locality:         strings.Join(rai.Certificate.Subject.Locality, ","),
		}
	} else if rai.CertificateRequest != nil {
		rai.Subject = api.Subject{
			CommonName:       rai.CertificateRequest.Subject.CommonName,
			Organization:     strings.Join(rai.CertificateRequest.Subject.Organization, ","),
			OrganizationUnit: strings.Join(rai.CertificateRequest.Subject.OrganizationalUnit, ","),
			Country:          strings.Join(rai.CertificateRequest.Subject.Country, ","),
			State:            strings.Join(rai.CertificateRequest.Subject.Province, ","),
			Locality:         strings.Join(rai.CertificateRequest.Subject.Locality, ","),
		}

	}

	return &rai
}
func toRemoteAccessIdentityDAO(dmsName string, d api.RemoteAccessIdentity) RemoteAccessIdentityDAO {
	rai := RemoteAccessIdentityDAO{
		DMSName:               dmsName,
		ExternalKeyGeneration: d.ExternalKeyGeneration,
		AuthorizedCAs:         d.AuthorizedCAs,
		SerialNumber:          d.SerialNumber,
	}

	if d.Certificate != nil {
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d.Certificate.Raw})
		pemEncoded := base64.StdEncoding.EncodeToString(pemBytes)
		rai.Certificate = pemEncoded
	}

	if d.CertificateRequest != nil {
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: d.CertificateRequest.Raw})
		pemEncoded := base64.StdEncoding.EncodeToString(pemBytes)
		rai.CertificateRequest = pemEncoded
	}

	return rai
}

func (d *StaticCADAO) toStaticCA() api.StaticCA {
	decodedBytes, err := base64.StdEncoding.DecodeString(d.Certificate)
	if err == nil {
		certBlock, _ := pem.Decode([]byte(decodedBytes))
		cert, _ := x509.ParseCertificate(certBlock.Bytes)
		return api.StaticCA{
			ID:          d.ID,
			Certificate: cert,
		}
	}

	return api.StaticCA{
		ID: d.ID,
	}
}

func toStaticCADAO(dmsName string, d api.StaticCA) StaticCADAO {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d.Certificate.Raw})
	pemEncoded := base64.StdEncoding.EncodeToString(pemBytes)

	return StaticCADAO{
		DMSName:     dmsName,
		ID:          d.ID,
		Certificate: pemEncoded,
	}
}

func (d *IdentityProfileDAO) toIdentityProfile() *api.IdentityProfile {
	duration := time.Duration(-1 * time.Second)
	duration, _ = time.ParseDuration(d.PreventiveRenewalInterval)

	cas := []api.StaticCA{}
	for _, ca := range d.StaticCAs {
		cas = append(cas, ca.toStaticCA())
	}

	return &api.IdentityProfile{
		GeneralSettings: api.IdentityProfileGeneralSettings{
			EnrollmentMode: api.EnrollmentMode(d.EnrollmentMode),
		},
		EnrollmentSettings: api.IdentityProfileEnrollmentSettings{
			AuthenticationMode: api.ESTAuthenticationMode(d.AuthenticationMode),
			Tags:               d.Tags,
			Icon:               d.Icon,
			Color:              d.Color,
			AuthorizedCA:       d.AuthorizedCA,
			BootstrapCAs:       d.BootstrapCAs,
		},
		ReerollmentSettings: api.IdentityProfileReenrollmentSettings{
			PreventiveRenewalInterval: duration,
		},
		CADistributionSettings: api.IdentityProfileCADistributionSettings{
			IncludeAuthorizedCA:        d.IncludeAuthorizedCA,
			IncludeBootstrapCAs:        d.IncludeBootstrapCAs,
			IncludeLamassuDownstreamCA: d.IncludeLamassuDownstreamCA,
			ManagedCAs:                 d.ManagedCAs,
			StaticCAs:                  cas,
		},
		PublishToAWS: d.PublishToAWS,
	}
}

func toIdentityProfileDAO(dmsName string, d api.IdentityProfile) IdentityProfileDAO {
	cas := []StaticCADAO{}
	for _, ca := range d.CADistributionSettings.StaticCAs {
		cas = append(cas, toStaticCADAO(dmsName, ca))
	}

	return IdentityProfileDAO{
		DMSName:                    dmsName,
		EnrollmentMode:             string(d.GeneralSettings.EnrollmentMode),
		AuthenticationMode:         string(d.EnrollmentSettings.AuthenticationMode),
		BootstrapCAs:               d.EnrollmentSettings.BootstrapCAs,
		AuthorizedCA:               d.EnrollmentSettings.AuthorizedCA,
		Icon:                       d.EnrollmentSettings.Icon,
		Color:                      d.EnrollmentSettings.Color,
		Tags:                       d.EnrollmentSettings.Tags,
		PreventiveRenewalInterval:  d.ReerollmentSettings.PreventiveRenewalInterval.String(),
		IncludeAuthorizedCA:        d.CADistributionSettings.IncludeAuthorizedCA,
		IncludeBootstrapCAs:        d.CADistributionSettings.IncludeBootstrapCAs,
		IncludeLamassuDownstreamCA: d.CADistributionSettings.IncludeLamassuDownstreamCA,
		ManagedCAs:                 d.CADistributionSettings.ManagedCAs,
		StaticCAs:                  cas,
		PublishToAWS:               d.PublishToAWS,
	}
}

func (d *DeviceManufacturingServiceDAO) toDeviceManufacturingService() api.DeviceManufacturingService {
	dms := api.DeviceManufacturingService{
		Name:                 d.Name,
		Status:               d.Status,
		CreationTimestamp:    d.CreationTimestamp,
		CloudDMS:             d.IsCloudDMS,
		IdentityProfile:      nil,
		RemoteAccessIdentity: nil,
	}

	if d.IsCloudDMS {
		dms.IdentityProfile = d.IdentityProfile.toIdentityProfile()
	} else {
		dms.RemoteAccessIdentity = d.RemoteAccessIdentity.toRemoteAccessIdentity()
	}

	return dms
}
func toDeviceManufacturingServiceDAO(d api.DeviceManufacturingService) DeviceManufacturingServiceDAO {
	dms := DeviceManufacturingServiceDAO{
		Name:              d.Name,
		Status:            d.Status,
		CreationTimestamp: d.CreationTimestamp,
		IsCloudDMS:        d.CloudDMS,
	}

	if d.CloudDMS {
		dms.IdentityProfile = toIdentityProfileDAO(d.Name, *d.IdentityProfile)
	} else {
		dms.RemoteAccessIdentity = toRemoteAccessIdentityDAO(d.Name, *d.RemoteAccessIdentity)
	}

	return dms
}

func (DeviceManufacturingServiceDAO) TableName() string {
	return "dms"
}

func (IdentityProfileDAO) TableName() string {
	return "identity_profile"
}

func (RemoteAccessIdentityDAO) TableName() string {
	return "remote_access_identity"
}

func (StaticCADAO) TableName() string {
	return "static_cas"
}

func NewPostgresDB(db *gorm.DB) repository.DeviceManufacturingServiceRepository {
	db.AutoMigrate(&StaticCADAO{})
	db.AutoMigrate(&IdentityProfileDAO{})
	db.AutoMigrate(&RemoteAccessIdentityDAO{})
	db.AutoMigrate(&DeviceManufacturingServiceDAO{})

	return &PostgresDBContext{db}
}

type PostgresDBContext struct {
	*gorm.DB
}

func (db *PostgresDBContext) Insert(ctx context.Context, dms api.DeviceManufacturingService) error {
	dmsDAO := toDeviceManufacturingServiceDAO(dms)
	dmsDAO.CreationTimestamp = time.Now()

	if err := db.WithContext(ctx).Model(&DeviceManufacturingServiceDAO{}).Create(&dmsDAO).Error; err != nil {
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

	var idProfileDAO IdentityProfileDAO
	db.WithContext(ctx).Model(&dms).Association("IdentityProfile").Find(&idProfileDAO)

	var staticCAsDAO []StaticCADAO
	db.WithContext(ctx).Model(&idProfileDAO).Association("StaticCAs").Find(&staticCAsDAO)

	var rai RemoteAccessIdentityDAO
	db.WithContext(ctx).Model(&dms).Association("RemoteAccessIdentity").Find(&rai)

	idProfileDAO.StaticCAs = staticCAsDAO

	dms.IdentityProfile = idProfileDAO
	dms.RemoteAccessIdentity = rai

	return dms.toDeviceManufacturingService(), nil
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
		dms, err := db.SelectByName(ctx, v.Name)
		if err != nil {
			continue
		}
		parsedDMSs = append(parsedDMSs, dms)
	}

	return int(totalDMSs), parsedDMSs, nil
}

func (db *PostgresDBContext) UpdateDMS(ctx context.Context, dms api.DeviceManufacturingService) error {
	var dmsToUpdate DeviceManufacturingServiceDAO
	if err := db.WithContext(ctx).Model(&DeviceManufacturingServiceDAO{}).Where("name = ?", dms.Name).First(&dmsToUpdate).Error; err != nil {
		return err
	}

	dmsDAO := toDeviceManufacturingServiceDAO(dms)

	if dms.CloudDMS {
		if err := db.Save(&dmsDAO.IdentityProfile).Error; err != nil {
			return err
		}
	} else {
		if err := db.Save(&dmsDAO.RemoteAccessIdentity).Error; err != nil {
			return err
		}
	}

	if err := db.Save(&dmsDAO).Error; err != nil {
		return err
	}

	return nil
}
