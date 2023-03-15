package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/errs"
	"github.com/lamassuiot/lamassuiot/pkg/helppers"
	"github.com/lamassuiot/lamassuiot/pkg/models"
	"github.com/lamassuiot/lamassuiot/pkg/remfuncs"
	"github.com/lamassuiot/lamassuiot/pkg/storage"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

type DeviceManagerService interface {
	ESTService
	CreateDevice(input CreateDeviceInput) (*models.Device, error)
	ProvisionDeviceSlot(input ProvisionDeviceSlotInput) (*models.Device, error)
}

type deviceManagerServiceImpl struct {
	devicesStorage    storage.DeviceManagerRepo
	caClient          CAService
	dmsClient         DMSManagerService
	remoteFuncEngines map[string]remfuncs.PluggableFunctionEngine
}

type ServiceDeviceManagerBuilder struct {
	CAClient          CAService
	DMSClient         DMSManagerService
	DevicesStorage    storage.DeviceManagerRepo
	RemoteFuncEngines map[string]remfuncs.PluggableFunctionEngine
}

func NewDeviceManagerService(builder ServiceDeviceManagerBuilder) DeviceManagerService {
	return &deviceManagerServiceImpl{
		caClient:          builder.CAClient,
		devicesStorage:    builder.DevicesStorage,
		dmsClient:         builder.DMSClient,
		remoteFuncEngines: builder.RemoteFuncEngines,
	}
}

type CreateDeviceInput struct {
	ID       string
	Alias    string
	Tags     []string
	Metadata map[string]string
	DMSID    string
}

func (svc deviceManagerServiceImpl) CreateDevice(input CreateDeviceInput) (*models.Device, error) {
	now := time.Now()

	device := &models.Device{
		ID:                              input.ID,
		Alias:                           input.Alias,
		Tags:                            input.Tags,
		Status:                          models.DeviceNoIdentity,
		Metadata:                        input.Metadata,
		DefaultSlot:                     nil,
		ExtraSlots:                      map[string]*models.Slot{},
		EmergencyReEnrollAuthentication: nil,
		ConnectionMetadata:              map[string]string{},
		DMSOwnerID:                      input.DMSID,
		CreationDate:                    now,
	}

	return svc.devicesStorage.Insert(context.Background(), device)
}

type ProvisionDeviceSlotInput struct {
	ID     string
	SlotID string
}

func (svc deviceManagerServiceImpl) ProvisionDeviceSlot(input ProvisionDeviceSlotInput) (*models.Device, error) {
	device, err := svc.devicesStorage.Select(context.Background(), input.ID)
	if err != nil {
		return nil, err
	}

	if device.DefaultSlot == nil {
		return nil, errs.SentinelAPIError{
			Status: http.StatusForbidden,
			Msg:    "device is not provisioned",
		}
	}

	_, ok := device.ExtraSlots[input.SlotID]
	if ok {
		return nil, errs.SentinelAPIError{
			Status: http.StatusForbidden,
			Msg:    fmt.Sprintf("slot '%s' already provisioned", input.SlotID),
		}
	}

	dms, err := svc.dmsClient.GetDMSByID(GetDMSByIDInput{
		ID: device.DMSOwnerID,
	})
	if err != nil {
		return nil, err
	}

	type remoteFuncSlotProvisionInput struct {
		Device *models.Device
		DMS    *models.DMS
	}

	type remoteFuncSlotProvisionOutput struct {
		SecretValue string
	}

	if !dms.CloudDMS {
		return nil, errs.SentinelAPIError{
			Status: http.StatusForbidden,
			Msg:    "device is owned by a DMS not controlled by the PKI",
		}
	}
	extraSlots := dms.IdentityProfile.EnrollmentSettings.DeviceProvisionSettings.ExtraSlots
	if containsSlot := slices.Contains(maps.Keys(extraSlots), input.SlotID); containsSlot {
		return nil, errs.SentinelAPIError{
			Status: http.StatusForbidden,
			Msg:    "slot already provisioned",
		}
	}
	slotSettings := extraSlots[input.SlotID]
	rfunc := slotSettings.RemoteFunc
	if rfunc != nil {
		rfengine := svc.remoteFuncEngines[rfunc.EngineID]
		if rfengine == nil {
			return nil, fmt.Errorf("remote function engine not found")
		}

		rfuncOut, err := rfengine.RunFunction(rfunc.FuncID, remoteFuncSlotProvisionInput{
			Device: device,
			DMS:    dms,
		})
		if err != nil {
			return nil, err
		}

		rfuncProvsionResult, ok := rfuncOut.(remoteFuncSlotProvisionOutput)
		if !ok {
			return nil, fmt.Errorf("remote function did not return a valid response. aborting slot porvisioning")
		}

		slotVal := rfuncProvsionResult.SecretValue
		if slotSettings.Confidential {
			deviceSlotCert := device.DefaultSlot.Secrets[device.DefaultSlot.ActiveVersion].(*x509.Certificate)
			devicePubKey := deviceSlotCert.PublicKey.(*rsa.PublicKey)
			slotValBytes, err := helppers.EncryptWithPublicKey([]byte(slotVal), devicePubKey)
			if err != nil {
				return nil, err
			}

			slotVal = string(slotValBytes)
		}

		newSlot := &models.Slot{
			DMSManaged:                  true,
			Status:                      models.SlotActive,
			ActiveVersion:               0,
			PreventiveReenrollmentDelta: slotSettings.PreventiveReenrollmentDelta,
			CriticalDetla:               slotSettings.CriticalDetla,
			SecretType:                  models.OtherSlotProfileType,
			Secrets: map[int]interface{}{
				0: slotVal,
			},
		}

		device.ExtraSlots[input.SlotID] = newSlot
		return svc.devicesStorage.Update(context.Background(), device)
	}

	//default slot provisioners
	return nil, fmt.Errorf("TODO")
}

type GetDeviceInput struct {
	ID string
}

func (svc deviceManagerServiceImpl) GetDevice(input GetDeviceInput) (*models.Device, error) {
	return svc.devicesStorage.Select(context.Background(), input.ID)
}

func (svc deviceManagerServiceImpl) Enroll(ctx context.Context, csr *x509.CertificateRequest, cert *x509.Certificate, aps string) (*x509.Certificate, error) {
	deviceID := csr.Subject.CommonName

	device, err := svc.GetDevice(GetDeviceInput{
		ID: deviceID,
	})
	if err != nil {
		return nil, err
	}

	if device.DefaultSlot != nil {
		return nil, errs.SentinelAPIError{
			Status: http.StatusForbidden,
			Msg:    "slot default already enrolled",
		}
	}

	dms, err := svc.dmsClient.GetDMSByID(GetDMSByIDInput{
		ID: cert.Subject.CommonName,
	})
	if err != nil {
		return nil, err
	}

	if dms.CloudDMS {
		return nil, errs.SentinelAPIError{
			Status: http.StatusForbidden,
			Msg:    "this device must be enrolled through the DMS Manager service",
		}
	}

	signedCert, err := svc.caClient.SignCertificate(SignCertificateInput{
		CAID:         aps,
		CertRequest:  (*models.X509CertificateRequest)(csr),
		Subject:      models.Subject{},
		SignVerbatim: true,
	})
	if err != nil {
		return nil, err
	}

	device.DefaultSlot = &models.Slot{
		DMSManaged:                  false,
		Status:                      models.SlotActive,
		ActiveVersion:               0,
		PreventiveReenrollmentDelta: dms.IdentityProfile.EnrollmentSettings.DeviceProvisionSettings.IdentitySlot.PreventiveReenrollmentDelta,
		CriticalDetla:               dms.IdentityProfile.EnrollmentSettings.DeviceProvisionSettings.IdentitySlot.CriticalReenrollmentDetla,
		SecretType:                  models.X509SlotProfileType,
		Secrets: map[int]interface{}{
			0: signedCert,
		},
	}

	key, err := generatePSKey()
	if err != nil {
		return nil, err
	}

	cipheredKey, err := helppers.EncryptWithPublicKey([]byte(key), signedCert.Certificate.PublicKey.(*rsa.PublicKey))
	if err != nil {
		return nil, err
	}

	device.EmergencyReEnrollAuthentication = &models.EmergencyReEnrollAuthentication{
		PreSharedKey:          base64.URLEncoding.EncodeToString(cipheredKey),
		UsedAt:                time.Time{},
		ValidityAfterFirstUse: time.Hour,
	}

	device.Status = models.DeviceActive

	device, err = svc.devicesStorage.Update(ctx, device)
	if err != nil {
		return nil, err
	}

	return (*x509.Certificate)(signedCert.Certificate), nil
}

func (svc deviceManagerServiceImpl) Reenroll(ctx context.Context, csr *x509.CertificateRequest, cert *x509.Certificate, aps string) (*x509.Certificate, error) {
	return nil, fmt.Errorf("TODO")
}

func (svc deviceManagerServiceImpl) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, cert *x509.Certificate, aps string) (*x509.Certificate, interface{}, error) {
	return nil, nil, fmt.Errorf("TODO")
}

func (svc deviceManagerServiceImpl) CACerts(ctx context.Context, aps string) ([]*x509.Certificate, error) {
	return nil, fmt.Errorf("TODO")
}

func generatePSKey() (string, error) {
	//rand key 256 bits - 32 bytes
	keyBytes := make([]byte, 32)

	_, err := rand.Read(keyBytes)
	if err != nil {
		return "", err
	}

	key := fmt.Sprintf("%x", keyBytes)

	return key, nil
}
