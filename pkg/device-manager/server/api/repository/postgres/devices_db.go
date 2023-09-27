package postgres

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"sort"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/api"
	devicesErrors "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/repository"
	"github.com/lamassuiot/lamassuiot/pkg/utils/common"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lib/pq"

	"gorm.io/gorm"
)

type CertificateDAO struct {
	SlotID              string `gorm:"primaryKey"`
	DeviceID            string `gorm:"primaryKey"`
	SerialNumber        string `gorm:"primaryKey"`
	CAName              string
	Certificate         string
	Status              models.CertificateStatus
	IsActiveCertificate bool
	RevocationTimestamp pq.NullTime
	RevocationReason    string
}

type SlotDAO struct {
	SlotID       string           `gorm:"primaryKey"`
	DeviceID     string           `gorm:"primaryKey"`
	Certificates []CertificateDAO `gorm:"foreignKey:SlotID,DeviceID;References:SlotID,DeviceID"`
}

type DeviceDAO struct {
	ID                 string `gorm:"primaryKey"`
	Alias              string
	DmsName            string
	Status             api.DeviceStatus
	AllowNewEnrollment bool
	Slots              []SlotDAO      `gorm:"foreignKey:DeviceID"`
	Tags               pq.StringArray `gorm:"type:text[]"`
	Description        string
	IconName           string
	IconColor          string
	CreationTimestamp  time.Time
}

func (DeviceDAO) TableName() string {
	return "devices"
}

func (SlotDAO) TableName() string {
	return "slots"
}

func (CertificateDAO) TableName() string {
	return "certificates"
}

func toDeviceDAO(d *api.Device) DeviceDAO {
	slots := make([]SlotDAO, 0)
	for _, slot := range d.Slots {
		slots = append(slots, toSlotDAO(*slot, d.ID))
	}

	return DeviceDAO{
		ID:                 d.ID,
		DmsName:            d.DmsName,
		Alias:              d.Alias,
		Status:             d.Status,
		AllowNewEnrollment: d.AllowNewEnrollment,
		Tags:               d.Tags,
		IconName:           d.IconName,
		IconColor:          d.IconColor,
		Description:        d.Description,
		Slots:              slots,
		CreationTimestamp:  d.CreationTimestamp,
	}
}

func (d DeviceDAO) toDevice() *api.Device {
	slots := make([]*api.Slot, 0)
	for _, slotDAO := range d.Slots {
		slot := slotDAO.toSlot()
		slots = append(slots, &slot)
	}

	return &api.Device{
		ID:                 d.ID,
		DmsName:            d.DmsName,
		Alias:              d.Alias,
		Status:             d.Status,
		AllowNewEnrollment: d.AllowNewEnrollment,
		Tags:               d.Tags,
		Slots:              slots,
		Description:        d.Description,
		IconName:           d.IconName,
		IconColor:          d.IconColor,
		CreationTimestamp:  d.CreationTimestamp,
	}
}

func (c *SlotDAO) toSlot() api.Slot {
	certificates := make([]*api.Certificate, 0)
	var activeCertificate *api.Certificate = nil

	for _, certificate := range c.Certificates {
		cert, err := certificate.toCertificate()
		if err != nil {
			continue
		}

		if certificate.IsActiveCertificate {
			activeCertificate = &cert
		} else {
			certificates = append(certificates, &cert)
		}
	}

	sort.Slice(certificates, func(x, y int) bool {
		return certificates[x].Certificate.NotBefore.After(certificates[y].Certificate.NotBefore)
	})

	return api.Slot{
		ID:                  c.SlotID,
		ArchiveCertificates: certificates,
		ActiveCertificate:   activeCertificate,
	}
}

func toSlotDAO(c api.Slot, deviceID string) SlotDAO {
	activeCertificate := c.ActiveCertificate

	certificates := make([]CertificateDAO, 0)
	for _, certificate := range c.ArchiveCertificates {
		certificates = append(certificates, toCertificateDAO(*certificate, c.ID, deviceID, false))
	}

	certificates = append(certificates, toCertificateDAO(*activeCertificate, c.ID, deviceID, true))

	return SlotDAO{
		SlotID:       c.ID,
		DeviceID:     deviceID,
		Certificates: certificates,
	}
}

func toCertificateDAO(c api.Certificate, slotID string, deviceID string, isActiveCertificate bool) CertificateDAO {
	certificate := ""
	if c.Certificate != nil {
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate.Raw})
		b64PemEncoded := base64.StdEncoding.EncodeToString(pemBytes)
		certificate = b64PemEncoded
	}

	return CertificateDAO{
		SlotID:              slotID,
		DeviceID:            deviceID,
		CAName:              c.CAName,
		SerialNumber:        c.SerialNumber,
		Certificate:         certificate,
		Status:              c.Status,
		RevocationTimestamp: c.RevocationTimestamp,
		RevocationReason:    c.RevocationReason,
		IsActiveCertificate: isActiveCertificate,
	}
}

func (c *CertificateDAO) toCertificate() (api.Certificate, error) {
	decodedCert, err := base64.StdEncoding.DecodeString(c.Certificate)
	if err != nil {
		return api.Certificate{}, errors.New("corrupted db: could not decode b64 certificate")
	}

	certBlock, _ := pem.Decode([]byte(decodedCert))
	if certBlock == nil {
		return api.Certificate{}, errors.New("corrupted db: could not decode pem certificate")
	}
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

	keyType, keySize, keyStrength := getPublicKeyInfo(cert)

	certificate := api.Certificate{
		CAName:              c.CAName,
		Status:              c.Status,
		SerialNumber:        c.SerialNumber,
		Subject:             subject,
		Certificate:         cert,
		ValidFrom:           cert.NotBefore,
		ValidTo:             cert.NotAfter,
		RevocationTimestamp: c.RevocationTimestamp,
		KeyMetadata: api.KeyStrengthMetadata{
			KeyType:     keyType,
			KeyBits:     keySize,
			KeyStrength: keyStrength,
		},
	}

	if c.RevocationTimestamp.Valid {
		certificate.RevocationReason = c.RevocationReason
	}

	return certificate, nil
}

func getPublicKeyInfo(cert *x509.Certificate) (api.KeyType, int, api.KeyStrength) {
	key := api.ParseKeyType(cert.PublicKeyAlgorithm.String())
	var keyBits int
	switch key {
	case api.RSA:
		keyBits = cert.PublicKey.(*rsa.PublicKey).N.BitLen()
	case api.ECDSA:
		keyBits = cert.PublicKey.(*ecdsa.PublicKey).Params().BitSize
	}

	var keyStrength api.KeyStrength = api.KeyStrengthLow
	switch key {
	case api.RSA:
		if keyBits < 2048 {
			keyStrength = api.KeyStrengthLow
		} else if keyBits >= 2048 && keyBits < 3072 {
			keyStrength = api.KeyStrengthMedium
		} else {
			keyStrength = api.KeyStrengthHigh
		}
	case api.ECDSA:
		if keyBits <= 128 {
			keyStrength = api.KeyStrengthLow
		} else if keyBits > 128 && keyBits < 256 {
			keyStrength = api.KeyStrengthMedium
		} else {
			keyStrength = api.KeyStrengthHigh
		}
	}

	return key, keyBits, keyStrength
}

func NewDevicesPostgresDB(db *gorm.DB) repository.Devices {
	db.AutoMigrate(&CertificateDAO{})
	db.AutoMigrate(&SlotDAO{})
	db.AutoMigrate(&DeviceDAO{})

	return &postgresDBContext{db}
}

type postgresDBContext struct {
	*gorm.DB
}

func (db *postgresDBContext) InsertDevice(ctx context.Context, device api.Device) error {
	deviceDAO := toDeviceDAO(&device)
	deviceDAO.CreationTimestamp = time.Now()
	if err := db.WithContext(ctx).Model(&DeviceDAO{}).Create(&deviceDAO).Error; err != nil {
		duplicationErr := &devicesErrors.DuplicateResourceError{
			ResourceType: "Device",
			ResourceId:   device.ID,
		}
		return duplicationErr
	}

	return nil
}

func (db *postgresDBContext) SelectDevices(ctx context.Context, queryParameters common.QueryParameters) (int, []*api.Device, error) {
	var totalDevices int64
	if err := db.WithContext(ctx).Model(&DeviceDAO{}).Count(&totalDevices).Error; err != nil {
		return 0, []*api.Device{}, err
	}

	var devicesDAO []DeviceDAO
	tx := db.WithContext(ctx).Model(&DeviceDAO{})
	tx = filters.ApplyQueryParametersFilters(tx, queryParameters)
	if err := tx.Find(&devicesDAO).Error; err != nil {
		return 0, []*api.Device{}, err
	}

	var devices []*api.Device
	for _, v := range devicesDAO {
		_, dev, err := db.SelectDeviceById(ctx, v.ID)
		if err != nil {
			continue
		}

		devices = append(devices, dev)
	}

	return int(totalDevices), devices, nil
}
func (db *postgresDBContext) SelectDevicesByStatus(ctx context.Context, status api.DeviceStatus, queryParameters common.QueryParameters) (int, []*api.Device, error) {
	var totalDevices int64
	if err := db.WithContext(ctx).Model(&DeviceDAO{}).Where("status = ?", status).Count(&totalDevices).Error; err != nil {
		return 0, []*api.Device{}, err
	}

	var devicesDAO []DeviceDAO
	tx := db.WithContext(ctx).Model(&DeviceDAO{}).Where("status = ?", status)
	tx = filters.ApplyQueryParametersFilters(tx, queryParameters)
	if err := tx.Find(&devicesDAO).Error; err != nil {
		return 0, []*api.Device{}, err
	}

	var devices []*api.Device
	for _, v := range devicesDAO {
		_, dev, err := db.SelectDeviceById(ctx, v.ID)
		if err != nil {
			continue
		}

		devices = append(devices, dev)
	}

	return int(totalDevices), devices, nil
}

func (db *postgresDBContext) SelectDeviceById(ctx context.Context, id string) (bool, *api.Device, error) {
	var device DeviceDAO
	if err := db.WithContext(ctx).Model(&DeviceDAO{}).Where("id = ?", id).First(&device).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, &api.Device{}, nil
		} else {
			return false, &api.Device{}, err
		}
	}

	var slots []SlotDAO
	db.WithContext(ctx).Model(&device).Association("Slots").Find(&slots)

	for i, v := range slots {
		var certificates []CertificateDAO
		db.WithContext(ctx).Model(&v).Association("Certificates").Find(&certificates)
		slots[i].Certificates = certificates
	}

	device.Slots = slots

	parsedDevice := device.toDevice()
	for i := 0; i < len(parsedDevice.Slots); i++ {
		sort.Slice(parsedDevice.Slots[i].ArchiveCertificates, func(x, y int) bool {
			return parsedDevice.Slots[i].ArchiveCertificates[x].Certificate.NotBefore.After(parsedDevice.Slots[i].ArchiveCertificates[y].Certificate.NotBefore)
		})
	}

	return true, parsedDevice, nil
}

func (db *postgresDBContext) SelectDevicesByDmsName(ctx context.Context, dmsName string, queryParameters common.QueryParameters) (int, []*api.Device, error) {
	var totalDevices int64
	if err := db.WithContext(ctx).Model(&DeviceDAO{}).Where("dms_name = ?", dmsName).Count(&totalDevices).Error; err != nil {
		return 0, []*api.Device{}, err
	}

	var devicesDAO []DeviceDAO
	tx := db.WithContext(ctx).Model(&DeviceDAO{}).Where("dms_name = ?", dmsName)
	tx = filters.ApplyQueryParametersFilters(tx, queryParameters)
	if err := tx.Find(&devicesDAO).Error; err != nil {
		return 0, []*api.Device{}, err
	}

	var devices []*api.Device
	for _, v := range devicesDAO {
		_, dev, err := db.SelectDeviceById(ctx, v.ID)
		if err != nil {
			continue
		}

		devices = append(devices, dev)
	}

	return int(totalDevices), devices, nil
}

func (db *postgresDBContext) UpdateDevice(ctx context.Context, device api.Device) error {
	deviceDAO := toDeviceDAO(&device)
	if err := db.Session(&gorm.Session{FullSaveAssociations: true}).Updates(&deviceDAO).Error; err != nil {
		return err
	}

	return nil
}

//***********************************************************************************************

func (db *postgresDBContext) InsertSlot(ctx context.Context, deviceID string, slot api.Slot) error {
	slotDAO := toSlotDAO(slot, deviceID)

	if err := db.WithContext(ctx).Model(&SlotDAO{}).Create(&slotDAO).Error; err != nil {
		duplicationErr := &devicesErrors.DuplicateResourceError{
			ResourceType: "Slot",
			ResourceId:   slotDAO.SlotID,
		}
		return duplicationErr
	}

	return nil
}

func (db *postgresDBContext) SelectSlots(ctx context.Context, deviceID string) ([]*api.Slot, error) {
	var slotsDAO []SlotDAO
	if err := db.WithContext(ctx).Model(&SlotDAO{}).Find(&slotsDAO).Error; err != nil {
		return []*api.Slot{}, err
	}

	for i, v := range slotsDAO {
		var certificates []CertificateDAO
		db.WithContext(ctx).Model(&v).Association("Certificates").Find(&certificates)
		slotsDAO[i].Certificates = certificates
	}

	var slotsList []*api.Slot
	for _, v := range slotsDAO {
		slot := v.toSlot()
		slotsList = append(slotsList, &slot)
	}

	return slotsList, nil
}
func (db *postgresDBContext) CountActiveCertificatesByStatus(ctx context.Context, status models.CertificateStatus) (int, error) {
	var totalCertificates int64
	if err := db.WithContext(ctx).Model(&CertificateDAO{}).Where("is_active_certificate = ?", true).Where("status = ?", status).Count(&totalCertificates).Error; err != nil {
		return 0, err
	}

	return int(totalCertificates), nil
}

func (db *postgresDBContext) SelectSlotByID(ctx context.Context, deviceID string, id string) (*api.Slot, error) {
	var slotDAO SlotDAO
	if err := db.WithContext(ctx).Model(&SlotDAO{}).Where("slot_id = ?", id).Where("device_id = ?", deviceID).First(&slotDAO).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			notFoundErr := &devicesErrors.ResourceNotFoundError{
				ResourceType: "Slot",
				ResourceId:   id,
			}
			return &api.Slot{}, notFoundErr
		} else {
			return &api.Slot{}, err
		}
	}

	var certificates []CertificateDAO
	db.WithContext(ctx).Model(&slotDAO).Association("Certificates").Find(&certificates)
	slotDAO.Certificates = certificates

	slot := slotDAO.toSlot()

	return &slot, nil
}

func (db *postgresDBContext) UpdateSlot(ctx context.Context, deviceID string, slot api.Slot) error {
	slotDAO := toSlotDAO(slot, deviceID)

	if err := db.Session(&gorm.Session{FullSaveAssociations: true}).Updates(&slotDAO).Error; err != nil {
		return err
	}

	return nil
}

//***********************************************************************************************

func (db *postgresDBContext) InsertCertificate(ctx context.Context, deviceID string, slotID string, certificate api.Certificate, isActiveCertificate bool) error {
	certificateDAO := toCertificateDAO(certificate, slotID, deviceID, isActiveCertificate)

	if err := db.WithContext(ctx).Model(&CertificateDAO{}).Create(&certificateDAO).Error; err != nil {
		duplicationErr := &devicesErrors.DuplicateResourceError{
			ResourceType: "Certificate",
			ResourceId:   certificateDAO.SerialNumber,
		}
		return duplicationErr
	}

	return nil
}

func (db *postgresDBContext) SelectCertificates(ctx context.Context, deviceID string, slotID string) ([]*api.Certificate, error) {
	var certificatesDAO []CertificateDAO
	if err := db.WithContext(ctx).Model(&CertificateDAO{}).Where("slot_id = ?", slotID).Where("device_id = ?", deviceID).Find(&certificatesDAO).Error; err != nil {
		return []*api.Certificate{}, err
	}

	var certificates []*api.Certificate
	for _, v := range certificatesDAO {
		slot, err := v.toCertificate()
		if err != nil {
			continue
		}
		certificates = append(certificates, &slot)
	}

	return certificates, nil
}

func (db *postgresDBContext) SelectCertificateBySerialNumber(ctx context.Context, deviceID string, slotID string, serialNumber string) (*api.Certificate, error) {
	var certificateDAO CertificateDAO
	if err := db.WithContext(ctx).Model(&CertificateDAO{}).Where("serial_number = ?", serialNumber).Where("slot_id = ?", slotID).Where("device_id = ?", deviceID).First(&certificateDAO).Error; err != nil {
		notFoundErr := &devicesErrors.ResourceNotFoundError{
			ResourceType: "Certificate",
			ResourceId:   serialNumber,
		}

		return &api.Certificate{}, notFoundErr
	}

	certificate, err := certificateDAO.toCertificate()
	if err != nil {
		return &api.Certificate{}, err
	}

	return &certificate, nil

}

func (db *postgresDBContext) UpdateCertificate(ctx context.Context, deviceID string, slotID string, certificate api.Certificate, isActiveCertificate bool) error {
	slotDAO := toCertificateDAO(certificate, slotID, deviceID, isActiveCertificate)
	if err := db.Updates(&slotDAO).Error; err != nil {
		return err
	}

	return nil
}
