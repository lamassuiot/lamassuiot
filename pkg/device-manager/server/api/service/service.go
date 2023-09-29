package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/api"
	deviceErrors "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/repository"
	dmsManagerClient "github.com/lamassuiot/lamassuiot/pkg/dms-manager/client"
	dmsManagerApi "github.com/lamassuiot/lamassuiot/pkg/dms-manager/common/api"
	estErrors "github.com/lamassuiot/lamassuiot/pkg/est/server/api/errors"
	estserver "github.com/lamassuiot/lamassuiot/pkg/est/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/utils"
	"github.com/lamassuiot/lamassuiot/pkg/utils/common"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/resources"
	serviceV3 "github.com/lamassuiot/lamassuiot/pkg/v3/services"
	"github.com/lib/pq"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
	"golang.org/x/exp/slices"
)

type Service interface {
	estserver.ESTService
	Health(ctx context.Context) bool
	GetStats(ctx context.Context, input *api.GetStatsInput) (*api.GetStatsOutput, error)

	CreateDevice(ctx context.Context, input *api.CreateDeviceInput) (*api.CreateDeviceOutput, error)
	UpdateDeviceMetadata(ctx context.Context, input *api.UpdateDeviceMetadataInput) (*api.UpdateDeviceMetadataOutput, error)
	DecommisionDevice(ctx context.Context, input *api.DecommisionDeviceInput) (*api.DecommisionDeviceOutput, error)
	GetDevices(ctx context.Context, input *api.GetDevicesInput) (*api.GetDevicesOutput, error)
	GetDeviceById(ctx context.Context, input *api.GetDeviceByIdInput) (*api.GetDeviceByIdOutput, error)
	GetDevicesByDMS(ctx context.Context, input *api.GetDevicesByDMSInput) (*api.GetDevicesByDMSOutput, error)

	ImportDeviceCert(ctx context.Context, input *api.ImportDeviceCertInput) (*api.ImportDeviceCertOutput, error)
	AddDeviceSlot(ctx context.Context, input *api.AddDeviceSlotInput) (*api.AddDeviceSlotOutput, error)
	UpdateActiveCertificateStatus(ctx context.Context, input *api.UpdateActiveCertificateStatusInput) (*api.UpdateActiveCertificateStatusOutput, error)
	RotateActiveCertificate(ctx context.Context, input *api.RotateActiveCertificateInput) (*api.RotateActiveCertificateOutput, error)
	RevokeActiveCertificate(ctx context.Context, input *api.RevokeActiveCertificateInput) (*api.RevokeActiveCertificateOutput, error)
	ForceReenroll(ctx context.Context, input *api.ForceReenrollInput) (*api.ForceReenrollOtput, error)
	GetDeviceLogs(ctx context.Context, input *api.GetDeviceLogsInput) (*api.GetDeviceLogsOutput, error)
	IsDMSAuthorizedToEnroll(ctx context.Context, input *api.IsDMSAuthorizedToEnrollInput) (*api.IsDMSAuthorizedToEnrollOutput, error)
}

type DevicesService struct {
	service                 Service
	devicesRepo             repository.Devices
	logsRepo                repository.DeviceLogs
	statsRepo               repository.Statistics
	caClient                serviceV3.CAService
	dmsManagerClient        dmsManagerClient.LamassuDMSManagerClient
	minimumReenrollmentDays int
	upstreamCACert          *x509.Certificate
}

func NewDeviceManagerService(upstreamCACert *x509.Certificate, devicesRepo repository.Devices, deviceLogsRep repository.DeviceLogs, statsRepo repository.Statistics, minimumReenrollmentDays int, caClient serviceV3.CAService, dmsManagerClient dmsManagerClient.LamassuDMSManagerClient) Service {
	svc := &DevicesService{
		devicesRepo:             devicesRepo,
		logsRepo:                deviceLogsRep,
		statsRepo:               statsRepo,
		caClient:                caClient,
		dmsManagerClient:        dmsManagerClient,
		minimumReenrollmentDays: minimumReenrollmentDays,
		upstreamCACert:          upstreamCACert,
	}

	svc.service = svc

	go func() {
		svc.ScanDevicesAndUpdateStatistics()
	}()

	return svc
}

func (s *DevicesService) SetService(svc Service) {
	s.service = svc
}

func (s *DevicesService) Health(ctx context.Context) bool {
	return true
}

func (s *DevicesService) GetStats(ctx context.Context, input *api.GetStatsInput) (*api.GetStatsOutput, error) {
	if input.ForceRefresh {
		s.ScanDevicesAndUpdateStatistics()
	}

	stats, time, err := s.statsRepo.GetStatistics(ctx)
	if err != nil {
		return &api.GetStatsOutput{}, err
	}

	return &api.GetStatsOutput{
		DevicesManagerStats: stats,
		ScanDate:            time,
	}, nil
}

func (s *DevicesService) CreateDevice(ctx context.Context, input *api.CreateDeviceInput) (*api.CreateDeviceOutput, error) {
	device := api.Device{
		Status:             api.DeviceStatusPendingProvisioning,
		ID:                 input.DeviceID,
		DmsName:            input.DmsName,
		AllowNewEnrollment: false,
		Alias:              input.Alias,
		Description:        input.Description,
		Tags:               input.Tags,
		IconName:           input.IconName,
		IconColor:          input.IconColor,
		Slots:              []*api.Slot{},
	}

	err := s.devicesRepo.InsertDevice(ctx, device)
	if err != nil {
		return nil, err
	}

	s.logsRepo.InsertDeviceLog(ctx, input.DeviceID, api.LogTypeSuccess, "Device Created", "")

	output, err := s.service.GetDeviceById(ctx, &api.GetDeviceByIdInput{
		DeviceID: input.DeviceID,
	})

	if err != nil {
		return nil, err
	}

	return &api.CreateDeviceOutput{
		Device: output.Device,
	}, nil
}

func (s *DevicesService) UpdateDeviceMetadata(ctx context.Context, input *api.UpdateDeviceMetadataInput) (*api.UpdateDeviceMetadataOutput, error) {
	outputGetDevice, err := s.service.GetDeviceById(ctx, &api.GetDeviceByIdInput{
		DeviceID: input.DeviceID,
	})

	if err != nil {
		return nil, err
	}

	device := outputGetDevice.Device
	device.Alias = input.Alias
	device.Description = input.Description
	device.AllowNewEnrollment = input.AllowNewEnrollment
	device.Tags = input.Tags
	device.IconName = input.IconName
	device.IconColor = input.IconColor

	s.devicesRepo.UpdateDevice(ctx, device)
	outputGetDevice, err = s.service.GetDeviceById(ctx, &api.GetDeviceByIdInput{
		DeviceID: input.DeviceID,
	})
	if err != nil {
		return nil, err
	}
	outputDeviceMetadatada := &api.UpdateDeviceMetadataOutput{
		Device: outputGetDevice.Device,
	}
	return outputDeviceMetadatada, nil
}

func (s *DevicesService) DecommisionDevice(ctx context.Context, input *api.DecommisionDeviceInput) (*api.DecommisionDeviceOutput, error) {
	outputGetDevice, err := s.service.GetDeviceById(ctx, &api.GetDeviceByIdInput{
		DeviceID: input.DeviceID,
	})

	if err != nil {
		return nil, err
	}

	s.logsRepo.InsertDeviceLog(ctx, input.DeviceID, api.LogTypeInfo, "Initiating Decommission Process", "All slots will be revoked")

	device := outputGetDevice.Device
	for i, slot := range device.Slots {
		outputRevokeSlot, err := s.service.RevokeActiveCertificate(ctx, &api.RevokeActiveCertificateInput{
			DeviceID:         input.DeviceID,
			SlotID:           slot.ID,
			RevocationReason: "Device is being decommissioned",
			CertSerialNumber: "",
		})

		if err != nil {
			log.Warn(fmt.Sprintf("Could not revoke slot [%s] certificate for device [%s]: %s", slot.ID, input.DeviceID, err))
			continue
		}

		device.Slots[i] = &outputRevokeSlot.Slot
	}

	device.Status = api.DeviceStatusDecommissioned

	err = s.devicesRepo.UpdateDevice(ctx, device)
	if err != nil {
		return nil, err
	}

	s.logsRepo.InsertDeviceLog(ctx, input.DeviceID, api.LogTypeInfo, "Decommissioned", "Decoomission process completed")

	outputGetDevice, err = s.service.GetDeviceById(ctx, &api.GetDeviceByIdInput{
		DeviceID: input.DeviceID,
	})
	if err != nil {
		return nil, err
	}

	return &api.DecommisionDeviceOutput{
		Device: outputGetDevice.Device,
	}, nil
}

func (s *DevicesService) GetDevices(ctx context.Context, input *api.GetDevicesInput) (*api.GetDevicesOutput, error) {
	totalDevices, devicesSubset, err := s.devicesRepo.SelectDevices(ctx, input.QueryParameters)
	if err != nil {
		return nil, err
	}

	devices := make([]api.Device, 0)
	for _, device := range devicesSubset {
		devices = append(devices, *device)
	}

	return &api.GetDevicesOutput{
		TotalDevices: totalDevices,
		Devices:      devices,
	}, nil
}

func (s *DevicesService) GetDevicesByDMS(ctx context.Context, input *api.GetDevicesByDMSInput) (*api.GetDevicesByDMSOutput, error) {
	totalDevices, devicesSubset, err := s.devicesRepo.SelectDevicesByDmsName(ctx, input.DmsName, input.QueryParameters)
	if err != nil {
		return nil, err
	}

	devices := make([]api.Device, 0)
	for _, device := range devicesSubset {
		devices = append(devices, *device)
	}

	return &api.GetDevicesByDMSOutput{
		TotalDevices: totalDevices,
		Devices:      devices,
	}, nil
}

func (s *DevicesService) GetDeviceById(ctx context.Context, input *api.GetDeviceByIdInput) (*api.GetDeviceByIdOutput, error) {
	exists, device, err := s.devicesRepo.SelectDeviceById(ctx, input.DeviceID)
	if err != nil {
		return nil, err
	}
	if !exists {
		return &api.GetDeviceByIdOutput{}, &deviceErrors.ResourceNotFoundError{
			ResourceType: "DEVICE",
			ResourceId:   input.DeviceID,
		}
	}
	return &api.GetDeviceByIdOutput{
		Device: *device,
	}, nil
}

func (s *DevicesService) AddDeviceSlot(ctx context.Context, input *api.AddDeviceSlotInput) (*api.AddDeviceSlotOutput, error) {
	outputGetDevice, err := s.service.GetDeviceById(ctx, &api.GetDeviceByIdInput{
		DeviceID: input.DeviceID,
	})

	if err != nil {
		return nil, err
	}

	device := outputGetDevice.Device

	for _, v := range device.Slots {
		if v.ID == input.SlotID {
			return nil, errors.New("slot name already exists")
		}
	}

	device.Slots = append(device.Slots, &api.Slot{
		ID: input.SlotID,
		ActiveCertificate: &api.Certificate{
			CAName:       input.ActiveCertificate.Issuer.CommonName,
			SerialNumber: utils.InsertNth(utils.ToHexInt(input.ActiveCertificate.SerialNumber), 2),
			Certificate:  input.ActiveCertificate,
			Status:       models.StatusActive,
			RevocationTimestamp: pq.NullTime{
				Valid: false,
				Time:  time.Time{},
			},
		},
		ArchiveCertificates: []*api.Certificate{},
	})

	if device.Status == api.DeviceStatusPendingProvisioning {
		device.Status = api.DeviceStatusFullyProvisioned
	}

	err = s.devicesRepo.UpdateDevice(ctx, device)
	if err != nil {
		return nil, err
	}

	s.logsRepo.InsertSlotLog(ctx, input.DeviceID, input.SlotID, api.LogTypeSuccess, "Slot Created", fmt.Sprintf("Slot uses certificate with serial number %s", utils.InsertNth(utils.ToHexInt(input.ActiveCertificate.SerialNumber), 2)))

	outputGetDevice, err = s.service.GetDeviceById(ctx, &api.GetDeviceByIdInput{
		DeviceID: input.DeviceID,
	})

	if err != nil {
		return nil, err
	}

	var slot *api.Slot = nil
	for _, s := range outputGetDevice.Device.Slots {
		if s.ID == input.SlotID {
			slot = s
			break
		}
	}

	return &api.AddDeviceSlotOutput{
		Slot: *slot,
	}, nil
}

func (s *DevicesService) UpdateActiveCertificateStatus(ctx context.Context, input *api.UpdateActiveCertificateStatusInput) (*api.UpdateActiveCertificateStatusOutput, error) {
	slot, err := s.devicesRepo.SelectSlotByID(ctx, input.DeviceID, input.SlotID)

	// if err != nil {
	// 	return nil, err
	// }

	// if slot.ActiveCertificate == nil {
	// 	return nil, errors.service.New("no active certificate found")
	// }

	// device, err := s.devicesRepo.SelectDeviceById(ctx, input.DeviceID)
	// if err != nil {
	// 	return nil, err
	// }

	// updateDevice := false
	// if input.Status == models.StatusRevoked || input.Status == models.StatusExpired {
	// 	slot.ActiveCertificate.Status = input.Status
	// 	device.Status = api.DeviceStatusProvisionedWithWarnings
	// 	updateDevice = true
	// } else {
	// 	slot.ActiveCertificate.Status = input.Status
	// 	if input.Status == models.StatusAboutToExpire {
	// 		device.Status = api.DeviceStatusRequiresAction
	// 		updateDevice = true
	// 	}
	// }

	// err = s.devicesRepo.UpdateSlot(ctx, input.DeviceID, *slot)
	// if err != nil {
	// 	return nil, err
	// }

	// if updateDevice {
	// 	s.devicesRepo.UpdateDevice(ctx, *device)
	// }

	slot, err = s.devicesRepo.SelectSlotByID(ctx, input.DeviceID, input.SlotID)
	if err != nil {
		return nil, err
	}

	return &api.UpdateActiveCertificateStatusOutput{
		Slot: *slot,
	}, nil
}

func (s *DevicesService) RotateActiveCertificate(ctx context.Context, input *api.RotateActiveCertificateInput) (*api.RotateActiveCertificateOutput, error) {
	slot, err := s.devicesRepo.SelectSlotByID(ctx, input.DeviceID, input.SlotID)
	if err != nil {
		return nil, err
	}

	if slot.ActiveCertificate == nil {
		return nil, errors.New("no active certificate found")
	}

	revokeOutput, err := s.service.RevokeActiveCertificate(ctx, &api.RevokeActiveCertificateInput{
		DeviceID:         input.DeviceID,
		SlotID:           input.SlotID,
		RevocationReason: "Certificate is being rotated",
		CertSerialNumber: "",
	})
	if err != nil {
		return nil, err
	}

	slot = &revokeOutput.Slot
	slot.ArchiveCertificates = append(slot.ArchiveCertificates, slot.ActiveCertificate)
	slot.ActiveCertificate = &api.Certificate{
		CAName:       input.NewCertificate.Issuer.CommonName,
		SerialNumber: utils.InsertNth(utils.ToHexInt(input.NewCertificate.SerialNumber), 2),
		Certificate:  input.NewCertificate,
		Status:       models.StatusActive,
		RevocationTimestamp: pq.NullTime{
			Valid: false,
			Time:  time.Time{},
		},
	}

	err = s.devicesRepo.UpdateSlot(ctx, input.DeviceID, *slot)
	if err != nil {
		return nil, err
	}

	s.logsRepo.InsertSlotLog(ctx, input.DeviceID, input.SlotID, api.LogTypeSuccess, "Slot Reneweal process Complete", fmt.Sprintf("Slot useses new certificate with serial number %s", utils.InsertNth(utils.ToHexInt(input.NewCertificate.SerialNumber), 2)))

	slot, err = s.devicesRepo.SelectSlotByID(ctx, input.DeviceID, input.SlotID)
	if err != nil {
		return nil, err
	}

	return &api.RotateActiveCertificateOutput{
		Slot: *slot,
	}, nil
}

func (s *DevicesService) ForceReenroll(ctx context.Context, input *api.ForceReenrollInput) (*api.ForceReenrollOtput, error) {
	// Does nothing, it is used by the AMQP Middleware to force a reenroll. Just return Device
	outputGetDevice, err := s.service.GetDeviceById(ctx, &api.GetDeviceByIdInput{
		DeviceID: input.DeviceID,
	})
	if err != nil {
		return &api.ForceReenrollOtput{}, err
	}
	var crt *x509.Certificate
	for i := 0; i < len(outputGetDevice.Slots); i++ {
		if input.SlotID == outputGetDevice.Slots[i].ID {
			crt = outputGetDevice.Slots[i].ActiveCertificate.Certificate
			break
		}
	}

	return &api.ForceReenrollOtput{
		DeviceID:      input.DeviceID,
		SlotID:        input.SlotID,
		ForceReenroll: input.ForceReenroll,
		Crt:           crt,
	}, nil
}

func (s *DevicesService) RevokeActiveCertificate(ctx context.Context, input *api.RevokeActiveCertificateInput) (*api.RevokeActiveCertificateOutput, error) {
	slot, err := s.devicesRepo.SelectSlotByID(ctx, input.DeviceID, input.SlotID)

	if err != nil {
		return &api.RevokeActiveCertificateOutput{}, err
	}

	if slot.ActiveCertificate == nil {
		return &api.RevokeActiveCertificateOutput{}, errors.New("no active certificate found")
	}
	if input.CertSerialNumber == "" {
		input.CertSerialNumber = slot.ActiveCertificate.SerialNumber
	}
	if slot.ActiveCertificate.Status == models.StatusRevoked {
		return &api.RevokeActiveCertificateOutput{}, errors.New("certificate is already revoked")
	}

	if slot.ActiveCertificate.Status == models.StatusExpired {
		return &api.RevokeActiveCertificateOutput{}, errors.New("certificate is expired")
	}
	var cert api.Certificate
	for i := 0; i < len(slot.ArchiveCertificates); i++ {
		if slot.ArchiveCertificates[i].SerialNumber == input.CertSerialNumber {
			cert = *slot.ArchiveCertificates[i]
		}
	}
	if cert.Status == models.StatusRevoked {
		return &api.RevokeActiveCertificateOutput{}, errors.New("certificate is already revoked")
	} else {
		revokeOutput, err := s.caClient.UpdateCertificateStatus(ctx, serviceV3.UpdateCertificateStatusInput{
			SerialNumber:     slot.ActiveCertificate.SerialNumber,
			NewStatus:        models.StatusRevoked,
			RevocationReason: ocsp.Superseded,
		})

		if err != nil {
			return &api.RevokeActiveCertificateOutput{}, err
		}

		revokedCertificateSerialNumber := slot.ActiveCertificate.SerialNumber

		slot.ActiveCertificate.Status = models.StatusRevoked
		slot.ActiveCertificate.RevocationReason = input.RevocationReason
		slot.ActiveCertificate.RevocationTimestamp = pq.NullTime{
			Valid: true,
			Time:  revokeOutput.RevocationTimestamp,
		}

		err = s.devicesRepo.UpdateSlot(ctx, input.DeviceID, *slot)
		if err != nil {
			return &api.RevokeActiveCertificateOutput{}, err
		}

		s.logsRepo.InsertSlotLog(ctx, input.DeviceID, input.SlotID, api.LogTypeWarn, "Certificate Revoked", fmt.Sprintf("The certificate %s will no longer be usable: %s", revokedCertificateSerialNumber, input.RevocationReason))

		slot, err = s.devicesRepo.SelectSlotByID(ctx, input.DeviceID, input.SlotID)
		if err != nil {
			return &api.RevokeActiveCertificateOutput{}, err
		}

		return &api.RevokeActiveCertificateOutput{
			Slot: *slot,
		}, nil
	}

}

func (s *DevicesService) GetDeviceLogs(ctx context.Context, input *api.GetDeviceLogsInput) (*api.GetDeviceLogsOutput, error) {
	outputGetDevice, err := s.service.GetDeviceById(ctx, &api.GetDeviceByIdInput{
		DeviceID: input.DeviceID,
	})
	if err != nil {
		return &api.GetDeviceLogsOutput{}, err
	}

	logs, err := s.logsRepo.SelectDeviceLogs(ctx, input.DeviceID)
	if err != nil {
		return &api.GetDeviceLogsOutput{}, err
	}

	deviceLogs := api.DeviceLogs{
		DevciceID: input.DeviceID,
		Logs:      logs,
		SlotLogs:  map[string][]api.Log{},
	}
	for _, v := range outputGetDevice.Slots {
		slotLogs, err := s.logsRepo.SelectSlotLogs(ctx, input.DeviceID, v.ID)
		if err != nil {
			continue
		}

		deviceLogs.SlotLogs[v.ID] = slotLogs
	}

	return &api.GetDeviceLogsOutput{
		DeviceLogs: deviceLogs,
	}, nil
}

func (s *DevicesService) IsDMSAuthorizedToEnroll(ctx context.Context, input *api.IsDMSAuthorizedToEnrollInput) (*api.IsDMSAuthorizedToEnrollOutput, error) {
	dmsOutput, err := s.dmsManagerClient.GetDMSByName(ctx, &dmsManagerApi.GetDMSByNameInput{
		Name: input.DMSName,
	})
	if err != nil {
		return nil, err
	}

	isAuthorized := false

	if dmsOutput.CloudDMS {
		isAuthorized = dmsOutput.IdentityProfile.EnrollmentSettings.AuthorizedCA == input.CAName
	} else {
		isAuthorized = slices.Contains(dmsOutput.RemoteAccessIdentity.AuthorizedCAs, input.CAName)
	}

	return &api.IsDMSAuthorizedToEnrollOutput{
		IsAuthorized: isAuthorized,
	}, nil
}

func (s *DevicesService) ImportDeviceCert(ctx context.Context, input *api.ImportDeviceCertInput) (*api.ImportDeviceCertOutput, error) {
	deviceCert, err := s.caClient.GetCertificateBySerialNumber(ctx, serviceV3.GetCertificatesBySerialNumberInput{
		SerialNumber: input.SerialNumber,
	})
	if err != nil {
		return &api.ImportDeviceCertOutput{}, err
	}

	if deviceCert.Subject.CommonName != input.DeviceID {
		return nil, &estErrors.GenericError{
			Message:    "Common Name and ID are not the same",
			StatusCode: 400,
		}
	}

	device, err := s.service.GetDeviceById(ctx, &api.GetDeviceByIdInput{
		DeviceID: input.DeviceID,
	})
	if err != nil {
		return &api.ImportDeviceCertOutput{}, err
	}

	dms, err := s.dmsManagerClient.GetDMSByName(ctx, &dmsManagerApi.GetDMSByNameInput{
		Name: device.DmsName,
	})
	if err != nil {
		return &api.ImportDeviceCertOutput{}, err
	}

	if dms.RemoteAccessIdentity.AuthorizedCAs[0] != input.CaName {
		return nil, &estErrors.GenericError{
			Message:    "CA is not authorized",
			StatusCode: 400,
		}
	}

	slot, err := s.service.AddDeviceSlot(ctx, &api.AddDeviceSlotInput{
		DeviceID:          input.DeviceID,
		SlotID:            input.SlotID,
		ActiveCertificate: (*x509.Certificate)(deviceCert.Certificate),
	})
	if err != nil {
		return &api.ImportDeviceCertOutput{}, err
	}

	return &api.ImportDeviceCertOutput{
		Slot: slot.Slot,
	}, nil
}

// -------------------------------------------------------------------------------------------------------------------
// 												EST Functions
// -------------------------------------------------------------------------------------------------------------------

func (s *DevicesService) CACerts(ctx context.Context, aps string) ([]*x509.Certificate, error) {
	cas := make([]*x509.Certificate, 0)
	s.caClient.GetCAs(ctx, serviceV3.GetCAsInput{
		QueryParameters: &resources.QueryParameters{},
		ExhaustiveRun:   true,
		ApplyFunc: func(c *models.CACertificate) {
			cas = append(cas, (*x509.Certificate)(c.Certificate.Certificate))
		},
	})
	return cas, nil
}

func (s *DevicesService) Enroll(ctx context.Context, csr *x509.CertificateRequest, clientCertificateChain []*x509.Certificate, aps string) (*x509.Certificate, error) {
	outGetCA, err := s.caClient.GetCAByID(ctx, serviceV3.GetCAByIDInput{
		CAID: string(models.CALocalRA),
	})
	if err != nil {
		return nil, &estErrors.GenericError{
			Message:    "CA not found",
			StatusCode: 404,
		}
	}
	dmsName := ctx.Value("dmsName").(string)
	dms, err := s.dmsManagerClient.GetDMSByName(ctx, &dmsManagerApi.GetDMSByNameInput{
		Name: dmsName,
	})
	if err != nil {
		return nil, err
	}

	if dms.DeviceManufacturingService.CloudDMS {
		err = s.verifyCertificate(clientCertificateChain[0], s.upstreamCACert, false)
		if err != nil {
			log.Debug("the presented client certificate was not issued by lms-lra nor by the Upstream CA")
			return nil, &estErrors.GenericError{
				Message:    "client certificate is not valid: " + err.Error(),
				StatusCode: 403,
			}
		}
	} else {
		err = s.verifyCertificate(clientCertificateChain[0], (*x509.Certificate)(outGetCA.Certificate.Certificate), false)
		if err != nil {
			log.Debug("the presented client certificate was not issued by lms-lra.")
			return nil, &estErrors.GenericError{
				Message:    "client certificate is not valid: " + err.Error(),
				StatusCode: 403,
			}
		}
	}

	isAuthroizedOutput, err := s.service.IsDMSAuthorizedToEnroll(ctx, &api.IsDMSAuthorizedToEnrollInput{
		DMSName: dms.DeviceManufacturingService.Name,
		CAName:  aps,
	})
	if err != nil {
		return nil, err
	}

	if !isAuthroizedOutput.IsAuthorized {
		return nil, &estErrors.GenericError{
			Message:    "DMS is not authorized to enroll with the selected APS",
			StatusCode: 403,
		}
	}

	csrCommonName := csr.Subject.CommonName
	splitedCsrCommonName := strings.Split(csrCommonName, ":")

	var slotID string = ""
	var deviceID string = ""
	if len(splitedCsrCommonName) == 1 {
		slotID = "default"
		deviceID = splitedCsrCommonName[0]
	} else if len(splitedCsrCommonName) == 2 {
		slotID = splitedCsrCommonName[0]
		if slotID == "default" {
			return nil, &estErrors.GenericError{
				Message:    "invalid common name format: 'default' is a reserved slotID",
				StatusCode: 400,
			}
		}
		deviceID = splitedCsrCommonName[1]
	} else {
		return nil, &estErrors.GenericError{
			Message:    "invalid common name format",
			StatusCode: 400,
		}
	}

	exists, getDevice, err := s.devicesRepo.SelectDeviceById(ctx, deviceID)
	if err != nil {
		log.Fatal("Could not detect provisioning status: ", err)
	}

	if !exists {
		_, err = s.service.CreateDevice(ctx, &api.CreateDeviceInput{
			DeviceID: deviceID,
			Alias:    deviceID,
			Tags: []string{
				clientCertificateChain[0].Subject.CommonName,
				aps,
			},
			DmsName:     dms.DeviceManufacturingService.Name,
			IconColor:   "#0068D1",
			IconName:    "Cg/CgSmartphoneChip",
			Description: fmt.Sprintf("New Device #%s", deviceID),
		})
		if err != nil {
			return nil, err
		}
	} else {
		device := getDevice
		if dms.DeviceManufacturingService.IdentityProfile != nil && !dms.DeviceManufacturingService.IdentityProfile.EnrollmentSettings.AllowNewAutoEnrollment {
			if device.Status == api.DeviceStatusDecommissioned {
				return nil, &estErrors.GenericError{
					Message:    "device is decommissioned",
					StatusCode: 403,
				}
			}

			for _, slot := range device.Slots {
				if slot.ID == slotID && slot.ActiveCertificate != nil {
					return nil, &estErrors.GenericError{
						Message:    "slot is already enrolled",
						StatusCode: 409,
					}
				}
			}
		}

	}

	signOutput, err := s.caClient.SignCertificate(ctx, serviceV3.SignCertificateInput{
		CAID:         aps,
		CertRequest:  (*models.X509CertificateRequest)(csr),
		Subject:      nil,
		SignVerbatim: true,
	})

	if err != nil {
		return nil, err
	}

	if dms.DeviceManufacturingService.IdentityProfile != nil && dms.DeviceManufacturingService.IdentityProfile.EnrollmentSettings.AllowNewAutoEnrollment && getDevice.Status == api.DeviceStatusFullyProvisioned {
		s.logsRepo.InsertSlotLog(ctx, deviceID, slotID, api.LogTypeInfo, "Auto Enrollment process", "Active Slot Enrollment")
		_, err = s.service.RotateActiveCertificate(ctx, &api.RotateActiveCertificateInput{
			DeviceID:       deviceID,
			SlotID:         slotID,
			NewCertificate: (*x509.Certificate)(signOutput.Certificate),
		})
		if err != nil {
			return nil, err
		}

	} else {
		_, err = s.service.AddDeviceSlot(ctx, &api.AddDeviceSlotInput{
			DeviceID:          deviceID,
			SlotID:            slotID,
			ActiveCertificate: (*x509.Certificate)(signOutput.Certificate),
		})
		if err != nil {
			return nil, err
		}
	}

	return (*x509.Certificate)(signOutput.Certificate), nil
}

func (s *DevicesService) Reenroll(ctx context.Context, csr *x509.CertificateRequest, cert *x509.Certificate, aps string) (*x509.Certificate, error) {
	csrCommonName := csr.Subject.CommonName
	splitedCsrCommonName := strings.Split(csrCommonName, ":")

	var slotID string = ""
	var deviceID string = ""
	if len(splitedCsrCommonName) == 1 {
		slotID = "default"
		deviceID = splitedCsrCommonName[0]
	} else if len(splitedCsrCommonName) == 2 {
		slotID = splitedCsrCommonName[0]
		deviceID = splitedCsrCommonName[1]
	} else {
		return nil, &estErrors.GenericError{
			Message:    "invalid common name format",
			StatusCode: 400,
		}
	}
	device, err := s.service.GetDeviceById(ctx, &api.GetDeviceByIdInput{
		DeviceID: deviceID,
	})
	if err != nil {
		return nil, &estErrors.GenericError{
			Message:    "Device dont exists",
			StatusCode: 400,
		}
	}
	dms, err := s.dmsManagerClient.GetDMSByName(ctx, &dmsManagerApi.GetDMSByNameInput{
		Name: device.Device.DmsName,
	})
	if err != nil {
		return nil, err
	}
	s.logsRepo.InsertSlotLog(ctx, deviceID, slotID, api.LogTypeInfo, "Slot Reneweal process Underway", "Certificate rotation request received")

	if dms.DeviceManufacturingService.CloudDMS {
		aps = dms.DeviceManufacturingService.IdentityProfile.EnrollmentSettings.AuthorizedCA
	} else {
		aps = cert.Issuer.CommonName
	}

	isAuthroizedOutput, err := s.service.IsDMSAuthorizedToEnroll(ctx, &api.IsDMSAuthorizedToEnrollInput{
		DMSName: dms.DeviceManufacturingService.Name,
		CAName:  aps,
	})
	if err != nil {
		return nil, err
	}
	if !isAuthroizedOutput.IsAuthorized {
		return nil, &estErrors.GenericError{
			Message:    "DMS is not authorized to enroll with the selected APS",
			StatusCode: 403,
		}
	}

	outGetCA, err := s.caClient.GetCAByID(ctx, serviceV3.GetCAByIDInput{
		CAID: aps,
	})

	if err != nil {
		s.logsRepo.InsertSlotLog(ctx, deviceID, slotID, api.LogTypeCritical, "Slot Reneweal process Failed", fmt.Sprintf("Could not retrive siging CA %s", aps))
		return nil, &estErrors.GenericError{
			Message:    "CA not found",
			StatusCode: 404,
		}
	}
	if dms.DeviceManufacturingService.CloudDMS {
		err = s.verifyCertificate(cert, s.upstreamCACert, false)
		if err != nil {
			s.logsRepo.InsertSlotLog(ctx, deviceID, slotID, api.LogTypeCritical, "Slot Reneweal process Failed", "Client certificate is not valid")
			return nil, &estErrors.GenericError{
				Message:    "client certificate is not valid: " + err.Error(),
				StatusCode: 403,
			}
		}
	} else {
		err = s.verifyCertificate(cert, (*x509.Certificate)(outGetCA.Certificate.Certificate), false)
		if err != nil {
			s.logsRepo.InsertSlotLog(ctx, deviceID, slotID, api.LogTypeCritical, "Slot Reneweal process Failed", "Client certificate is not valid")
			return nil, &estErrors.GenericError{
				Message:    "client certificate is not valid: " + err.Error(),
				StatusCode: 403,
			}
		}
	}

	if int(time.Until(cert.NotAfter).Hours())/24 > s.minimumReenrollmentDays {
		s.logsRepo.InsertSlotLog(ctx, deviceID, slotID, api.LogTypeCritical, "Slot Reneweal process Failed", fmt.Sprintf("Certificate can only be renewed %d days before expiration", s.minimumReenrollmentDays))
		return nil, &estErrors.GenericError{
			Message:    fmt.Sprintf("Certificate can only be renewed %d days before expiration", s.minimumReenrollmentDays),
			StatusCode: 403,
		}
	}

	signOutput, err := s.caClient.SignCertificate(ctx, serviceV3.SignCertificateInput{
		CAID:         aps,
		CertRequest:  (*models.X509CertificateRequest)(csr),
		Subject:      nil,
		SignVerbatim: true,
	})
	if err != nil {
		return nil, err
	}

	_, err = s.service.RotateActiveCertificate(ctx, &api.RotateActiveCertificateInput{
		DeviceID:       deviceID,
		SlotID:         slotID,
		NewCertificate: (*x509.Certificate)(signOutput.Certificate),
	})
	if err != nil {
		return nil, err
	}

	return (*x509.Certificate)(signOutput.Certificate), nil
}

func (s *DevicesService) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, cert *x509.Certificate, aps string) (*x509.Certificate, *rsa.PrivateKey, error) {
	csrkey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	csr, err = s.generateCSR(csr, csrkey)
	if err != nil {
		return nil, nil, err
	}

	crt, err := s.service.Enroll(ctx, csr, []*x509.Certificate{cert}, aps)
	if err != nil {
		return nil, nil, err
	}

	return crt, csrkey, nil
}

// -------------------------------------------------------------------------------------------------------------------
// 													UTILS
// -------------------------------------------------------------------------------------------------------------------

func (s *DevicesService) verifyCertificate(clientCertificate *x509.Certificate, caCertificate *x509.Certificate, allowExpiredRenewal bool) error {
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(caCertificate)

	opts := x509.VerifyOptions{
		Roots:     clientCAs,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cert, _ := s.caClient.GetCertificateBySerialNumber(context.Background(), serviceV3.GetCertificatesBySerialNumberInput{
		SerialNumber: utils.InsertNth(utils.ToHexInt(clientCertificate.SerialNumber), 2),
	})
	_, err := clientCertificate.Verify(opts)
	if err != nil {
		if cert.Status != models.StatusExpired && !allowExpiredRenewal {
			return errors.New("could not verify client certificate: " + err.Error())
		} else if cert.Status == models.StatusExpired && !allowExpiredRenewal {
			return errors.New("could not verify client certificate: " + err.Error())
		}
	}

	if cert.Status == models.StatusRevoked {
		return errors.New("certificate status is: " + string(cert.Status))
	}

	return nil
}

func (s *DevicesService) generateCSR(csr *x509.CertificateRequest, key interface{}) (*x509.CertificateRequest, error) {
	template := &x509.CertificateRequest{
		Subject: csr.Subject,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %v", err)
	}

	csrNew, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate request: %v", err)
	}
	return csrNew, nil
}

func (s *DevicesService) ScanDevicesAndUpdateStatistics() {
	ctx := context.Background()
	t0 := time.Now()
	log.Info("Starting devices scan...")
	deviceStats := map[api.DeviceStatus]int{}
	slotStatus := map[models.CertificateStatus]int{}

	deviceStatusList := []api.DeviceStatus{
		api.DeviceStatusPendingProvisioning,
		api.DeviceStatusFullyProvisioned,
		api.DeviceStatusRequiresAction,
		api.DeviceStatusProvisionedWithWarnings,
		api.DeviceStatusDecommissioned,
	}

	for _, status := range deviceStatusList {
		var total = -1
		total, _, err := s.devicesRepo.SelectDevicesByStatus(ctx, status, common.QueryParameters{})
		if err != nil {
			log.Warn(fmt.Sprintf("Could not get a list of devices with [%s] status: ", status), err)
		}
		deviceStats[status] = total
	}

	slotStatusList := []models.CertificateStatus{
		models.StatusActive,
		models.StatusExpired,
		models.StatusRevoked,
	}

	for _, status := range slotStatusList {
		var total = -1
		total, err := s.devicesRepo.CountActiveCertificatesByStatus(ctx, status)
		if err != nil {
			log.Warn(fmt.Sprintf("Could not get a list of slots with [%s] status: ", status), err)
		}
		slotStatus[status] = total
	}

	s.statsRepo.UpdateStatistics(ctx, api.DevicesManagerStats{
		DevicesStats: deviceStats,
		SlotsStats:   slotStatus,
	})

	log.Info("Scan devices finished in " + time.Since(t0).String())
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
