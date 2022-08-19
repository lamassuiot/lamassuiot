package postgres

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/log/level"
	"github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	caerrors "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/repository"
	"github.com/lamassuiot/lamassuiot/pkg/utils/common"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"
	"github.com/lib/pq"

	"github.com/lamassuiot/lamassuiot/pkg/utils"
	"gorm.io/gorm"
)

type CertificateDAO struct {
	SerialNumber     string `gorm:"primaryKey"`
	CAName           string
	CAType           api.CAType `gorm:"column:type"`
	Certificate      string
	Status           api.CertificateStatus
	CreationTs       time.Time
	RevocationTs     pq.NullTime
	RevocationReason string
}

func (CertificateDAO) TableName() string {
	return "certificates"
}

type CertificateAuthorityDAO struct {
	CertificateDAO
	IssuanceDuration int
}

func (c *CertificateAuthorityDAO) toCertificate() (api.CACertificate, error) {
	decodedCert, err := base64.StdEncoding.DecodeString(strings.Trim(c.Certificate, " "))
	if err != nil {
		return api.CACertificate{}, errors.New("corrupted db: could not decode b64 certificate")
	}

	certBlock, _ := pem.Decode([]byte(decodedCert))
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return api.CACertificate{}, errors.New("corrupted db: could not inflate certificate")
	}

	subject := api.Subject{
		CommonName: cert.Subject.CommonName,
	}

	if len(cert.Subject.Country) > 0 {
		subject.Country = cert.Subject.Country[0]
	}
	if len(cert.Subject.Organization) > 0 {
		subject.Organization = cert.Subject.Organization[0]
	}
	if len(cert.Subject.OrganizationalUnit) > 0 {
		subject.OrganizationUnit = cert.Subject.OrganizationalUnit[0]
	}
	if len(cert.Subject.Locality) > 0 {
		subject.Locality = cert.Subject.Locality[0]
	}
	if len(cert.Subject.Province) > 0 {
		subject.State = cert.Subject.Province[0]
	}

	certificate := api.CACertificate{
		Certificate: api.Certificate{
			CAName:              c.CAName,
			Status:              c.Status,
			SerialNumber:        c.SerialNumber,
			Subject:             subject,
			Certificate:         cert,
			ValidFrom:           cert.NotBefore,
			ValidTo:             cert.NotAfter,
			RevocationTimestamp: c.RevocationTs,
		},
		IssuanceDuration: time.Duration(c.IssuanceDuration * int(time.Second)),
	}

	if c.RevocationTs.Valid {
		certificate.RevocationReason = c.RevocationReason
	}

	return certificate, nil

}

func (CertificateAuthorityDAO) TableName() string {
	return "certificate_authorites"
}

func (c *CertificateDAO) toCertificate() (api.Certificate, error) {
	decodedCert, err := base64.StdEncoding.DecodeString(c.Certificate)
	if err != nil {
		return api.Certificate{}, errors.New("corrupted db: could not decode b64 certificate")
	}

	certBlock, _ := pem.Decode([]byte(decodedCert))
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return api.Certificate{}, errors.New("corrupted db: could not inflate certificate")
	}

	subject := api.Subject{
		CommonName: cert.Subject.CommonName,
	}

	if len(cert.Subject.Country) > 0 {
		subject.Country = cert.Subject.Country[0]
	}
	if len(cert.Subject.Organization) > 0 {
		subject.Organization = cert.Subject.Organization[0]
	}
	if len(cert.Subject.OrganizationalUnit) > 0 {
		subject.OrganizationUnit = cert.Subject.OrganizationalUnit[0]
	}
	if len(cert.Subject.Locality) > 0 {
		subject.Locality = cert.Subject.Locality[0]
	}
	if len(cert.Subject.Province) > 0 {
		subject.State = cert.Subject.Province[0]
	}

	certificate := api.Certificate{
		CAName:              c.CAName,
		Status:              c.Status,
		SerialNumber:        c.SerialNumber,
		Subject:             subject,
		Certificate:         cert,
		ValidFrom:           cert.NotBefore,
		ValidTo:             cert.NotAfter,
		RevocationTimestamp: c.RevocationTs,
	}

	if c.RevocationTs.Valid {
		certificate.RevocationReason = c.RevocationReason
	}

	return certificate, nil
}

type IssuedCertsTable struct {
	SerialNumber     string `gorm:"primaryKey"`
	Certificate      string
	CAName           string `gorm:"column_name:name"`
	CAType           string `gorm:"column_name:type"`
	Status           string
	RevocationTs     pq.NullTime
	RevocationReason string
	CreationTs       time.Time
}

func NewPostgresDB(db *gorm.DB, logger log.Logger) repository.Certificates {
	db.AutoMigrate(&CertificateAuthorityDAO{})
	db.AutoMigrate(&CertificateDAO{})

	return &PostgresDBContext{db, logger}
}

type PostgresDBContext struct {
	*gorm.DB
	logger log.Logger
}

func (db *PostgresDBContext) UpdateCertificateStatus(ctx context.Context, CAType api.CAType, CAName string, serialNumber string, status api.CertificateStatus, revocationReason string) error {
	var certifcate CertificateDAO

	if err := db.Model(&CertificateDAO{}).Where("serial_number = ?", serialNumber).First(&certifcate).Error; err != nil {
		level.Debug(db.logger).Log("msg", "Could not obtain CAs from database")
		notFoundErr := &caerrors.ResourceNotFoundError{
			ResourceType: "Certificate",
			ResourceId:   serialNumber,
		}
		return notFoundErr
	}

	certifcate.Status = status
	if status == api.StatusRevoked {
		certifcate.RevocationTs = pq.NullTime{
			Time:  time.Now(),
			Valid: true,
		}
		certifcate.RevocationReason = revocationReason
	}

	db.Save(&certifcate)

	return nil
}

func (db PostgresDBContext) InsertCertificate(ctx context.Context, CAType api.CAType, CAName string, certificate *x509.Certificate) error {
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	enc := make([]byte, base64.StdEncoding.EncodedLen(len(pemCert)))
	base64.StdEncoding.Encode(enc, pemCert)

	tx := db.Model(&CertificateDAO{}).Create(&CertificateDAO{
		Status:       api.StatusIssued,
		SerialNumber: utils.InsertNth(utils.ToHexInt(certificate.SerialNumber), 2),
		CAName:       CAName,
		CAType:       CAType,
		Certificate:  string(enc),
		CreationTs:   time.Now(),
	})

	if tx.Error != nil {
		duplicationErr := &caerrors.DuplicateResourceError{
			ResourceType: "Certificate",
			ResourceId:   utils.InsertNth(utils.ToHexInt(certificate.SerialNumber), 2),
		}
		return duplicationErr
	}

	return nil
}

func (db PostgresDBContext) SelectCertificatesByCA(ctx context.Context, CAType api.CAType, CAName string, queryParameters common.QueryParameters) (int, []api.Certificate, error) {
	var totalCertificates int64
	tx := db.Model(&CertificateDAO{}).Where("type = ?", CAType)
	tx = filters.ApplyFilters(tx, queryParameters.Filters) // only count certificates that match the filters
	if err := tx.Count(&totalCertificates).Error; err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not obtain CAs from database")
		return 0, []api.Certificate{}, err
	}

	var certificates []CertificateDAO
	tx = db.Model(&CertificateDAO{}).Where("ca_name = ?", CAName).Where("type = ?", CAType)
	tx = filters.ApplyQueryParametersFilters(tx, queryParameters)
	if err := tx.Find(&certificates).Error; err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not obtain Certificates from database")
		return 0, []api.Certificate{}, err
	}

	var parsedCertificates []api.Certificate
	for _, v := range certificates {
		certificate, err := v.toCertificate()
		if err != nil {
			level.Debug(db.logger).Log("err", err)
			continue
		}
		parsedCertificates = append(parsedCertificates, certificate)
	}

	return int(totalCertificates), parsedCertificates, nil
}

func (db PostgresDBContext) SelectCertificateBySerialNumber(ctx context.Context, CAType api.CAType, CAName string, serialNumber string) (api.Certificate, error) {
	var cert CertificateDAO
	if err := db.Model(&CertificateDAO{}).Where("ca_name = ?", CAName).Where("type = ?", CAType).Where("serial_number = ?", serialNumber).First(&cert).Error; err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not obtain CAs from database")
		notFoundErr := &caerrors.ResourceNotFoundError{
			ResourceType: "Certificate",
			ResourceId:   serialNumber,
		}
		return api.Certificate{}, notFoundErr
	}

	return cert.toCertificate()
}

func (db PostgresDBContext) UpdateCAStatus(ctx context.Context, CAType api.CAType, CAName string, status api.CertificateStatus, revocationReason string) error {
	var ca CertificateAuthorityDAO
	db.Model(&CertificateAuthorityDAO{}).Where("ca_name = ?", CAName).Where("type = ?", CAType).First(&ca)

	if ca.SerialNumber == "" {
		level.Debug(db.logger).Log("msg", "Could not obtain CAs from database")
		notFoundErr := &caerrors.ResourceNotFoundError{
			ResourceType: "CA",
			ResourceId:   CAName,
		}
		return notFoundErr
	}

	ca.Status = status
	if status == api.StatusRevoked {
		ca.RevocationTs = pq.NullTime{
			Time:  time.Now(),
			Valid: true,
		}
		ca.RevocationReason = revocationReason
	}

	db.Save(&ca)

	return nil
}

func (db PostgresDBContext) InsertCA(ctx context.Context, CAType api.CAType, certificate *x509.Certificate, issuanceDuration time.Duration) error {
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	enc := make([]byte, base64.StdEncoding.EncodedLen(len(pemCert)))
	base64.StdEncoding.Encode(enc, pemCert)

	tx := db.Model(&CertificateAuthorityDAO{}).Create(&CertificateAuthorityDAO{
		CertificateDAO: CertificateDAO{
			Status:       api.StatusIssued,
			SerialNumber: utils.InsertNth(utils.ToHexInt(certificate.SerialNumber), 2),
			CAName:       certificate.Subject.CommonName,
			CAType:       CAType,
			Certificate:  string(enc),
			CreationTs:   time.Now(),
		},
		IssuanceDuration: int(issuanceDuration.Seconds()),
	})
	if tx.Error != nil {
		duplicationErr := &caerrors.DuplicateResourceError{
			ResourceType: "CA",
			ResourceId:   certificate.Subject.CommonName,
		}
		return duplicationErr
	}

	return nil
}

func (db PostgresDBContext) SelectCAByName(ctx context.Context, CAType api.CAType, CAName string) (api.CACertificate, error) {
	var ca CertificateAuthorityDAO
	if err := db.Model(&CertificateAuthorityDAO{}).Where("ca_name = ?", CAName).Where("type = ?", CAType).First(&ca).Error; err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not obtain CAs from database")
		notFoundErr := &caerrors.ResourceNotFoundError{
			ResourceType: "CA",
			ResourceId:   CAName,
		}
		return api.CACertificate{}, notFoundErr
	}

	return ca.toCertificate()
}

func (db PostgresDBContext) SelectCAs(ctx context.Context, CAType api.CAType, queryParameters common.QueryParameters) (int, []api.CACertificate, error) {
	var totalCAs int64
	tx := db.Model(&CertificateAuthorityDAO{}).Where("type = ?", CAType)
	tx = filters.ApplyFilters(tx, queryParameters.Filters) // only count cas that match the filters
	if err := tx.Count(&totalCAs).Error; err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not obtain CAs from database")
		return 0, []api.CACertificate{}, err
	}

	tx = db.Model(&CertificateAuthorityDAO{}).Where("type = ?", CAType)
	tx = filters.ApplyQueryParametersFilters(tx, queryParameters)

	var cas []CertificateAuthorityDAO
	tx = tx.Scan(&cas)
	if tx.RowsAffected == 0 {
		// level.Debug(db.logger).Log("msg", "Could not obtain CAs from database with the given filters")
		return 0, []api.CACertificate{}, nil
	}

	var certs []api.CACertificate
	for _, v := range cas {
		cert, err := v.toCertificate()
		if err != nil {
			level.Debug(db.logger).Log("err", err)
			continue
		}

		certs = append(certs, cert)
	}

	return int(totalCAs), certs, nil
}
