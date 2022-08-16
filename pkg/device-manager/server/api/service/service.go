package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/log/level"
	caClient "github.com/lamassuiot/lamassuiot/pkg/ca/client"
	caApi "github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/api"
	deviceErrors "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/errors"
	dmsManagerClient "github.com/lamassuiot/lamassuiot/pkg/dms-manager/client"
	dmsManagerApi "github.com/lamassuiot/lamassuiot/pkg/dms-manager/common/api"
	estErrors "github.com/lamassuiot/lamassuiot/pkg/est/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/utils"
	"github.com/lamassuiot/lamassuiot/pkg/utils/common"
	"github.com/lib/pq"
	"golang.org/x/exp/slices"

	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/repository"
	estserver "github.com/lamassuiot/lamassuiot/pkg/est/server/api/service"
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
	CheckAndUpdateDeviceStatus(ctx context.Context, input *api.CheckAndUpdateDeviceStatusInput) (*api.CheckAndUpdateDeviceStatusOutput, error)
	IterateDevicesWithPredicate(ctx context.Context, input *api.IterateDevicesWithPredicateInput) (*api.IterateDevicesWithPredicateOutput, error)

	AddDeviceSlot(ctx context.Context, input *api.AddDeviceSlotInput) (*api.AddDeviceSlotOutput, error)
	UpdateActiveCertificateStatus(ctx context.Context, input *api.UpdateActiveCertificateStatusInput) (*api.UpdateActiveCertificateStatusOutput, error)
	RotateActiveCertificate(ctx context.Context, input *api.RotateActiveCertificateInput) (*api.RotateActiveCertificateOutput, error)
	RevokeActiveCertificate(ctx context.Context, input *api.RevokeActiveCertificateInput) (*api.RevokeActiveCertificateOutput, error)

	AddDeviceLog(ctx context.Context, input *api.AddDeviceLogInput) (*api.AddDeviceLogOutput, error)
	GetDeviceLogs(ctx context.Context, input *api.GetDeviceLogsInput) (*api.GetDeviceLogsOutput, error)

	IsDMSAuthorizedToEnroll(ctx context.Context, input *api.IsDMSAuthorizedToEnrollInput) (*api.IsDMSAuthorizedToEnrollOutput, error)
}

type devicesService struct {
	devicesRepo             repository.Devices
	logsRepo                repository.DeviceLogs
	statsRepo               repository.Statistics
	logger                  log.Logger
	caClient                caClient.LamassuCAClient
	dmsManagerClient        dmsManagerClient.LamassuDMSManagerClient
	minimumReenrollmentDays int
}

func NewDeviceManagerService(logger log.Logger, devicesRepo repository.Devices, deviceLogsRep repository.DeviceLogs, statsRepo repository.Statistics, minimumReenrollmentDays int, caClient caClient.LamassuCAClient, dmsManagerClient dmsManagerClient.LamassuDMSManagerClient) Service {
	return &devicesService{
		devicesRepo:             devicesRepo,
		logsRepo:                deviceLogsRep,
		statsRepo:               statsRepo,
		logger:                  logger,
		caClient:                caClient,
		dmsManagerClient:        dmsManagerClient,
		minimumReenrollmentDays: minimumReenrollmentDays,
	}
}

func (s *devicesService) Health(ctx context.Context) bool {
	return true
}

func (s *devicesService) GetStats(ctx context.Context, input *api.GetStatsInput) (*api.GetStatsOutput, error) {
	return &api.GetStatsOutput{}, nil
}

func (s *devicesService) CreateDevice(ctx context.Context, input *api.CreateDeviceInput) (*api.CreateDeviceOutput, error) {
	device := api.Device{
		Status:      api.DeviceStatusPendingProvisioning,
		ID:          input.DeviceID,
		Alias:       input.Alias,
		Description: input.Description,
		Tags:        input.Tags,
		IconName:    input.IconName,
		IconColor:   input.IconColor,
		Slots:       []*api.Slot{},
	}

	err := s.devicesRepo.InsertDevice(ctx, device)
	if err != nil {
		return nil, err
	}

	output, err := s.GetDeviceById(ctx, &api.GetDeviceByIdInput{
		DeviceID: input.DeviceID,
	})

	if err != nil {
		return nil, err
	}

	return &api.CreateDeviceOutput{
		Device: output.Device,
	}, nil
}

func (s *devicesService) UpdateDeviceMetadata(ctx context.Context, input *api.UpdateDeviceMetadataInput) (*api.UpdateDeviceMetadataOutput, error) {
	outputGetDevice, err := s.GetDeviceById(ctx, &api.GetDeviceByIdInput{
		DeviceID: input.DeviceID,
	})

	if err != nil {
		return nil, err
	}

	device := outputGetDevice.Device
	device.Alias = input.Alias
	device.Description = input.Description
	device.Tags = input.Tags
	device.IconName = input.IconName
	device.IconColor = input.IconColor

	s.devicesRepo.UpdateDevice(ctx, device)
	return &api.UpdateDeviceMetadataOutput{}, nil
}

func (s *devicesService) DecommisionDevice(ctx context.Context, input *api.DecommisionDeviceInput) (*api.DecommisionDeviceOutput, error) {
	outputGetDevice, err := s.GetDeviceById(ctx, &api.GetDeviceByIdInput{
		DeviceID: input.DeviceID,
	})

	if err != nil {
		return nil, err
	}

	device := outputGetDevice.Device
	for i, slot := range device.Slots {
		outputRevokeSlot, err := s.RevokeActiveCertificate(ctx, &api.RevokeActiveCertificateInput{
			DeviceID:         input.DeviceID,
			SlotID:           slot.ID,
			RevocationReason: "Device is decommissioned",
		})

		if err != nil {
			level.Debug(s.logger).Log("err", err, "msg", "Could not revoke slot "+slot.ID+" certificate for device "+input.DeviceID)
			continue
		}

		device.Slots[i] = &outputRevokeSlot.Slot
	}

	device.Status = api.DeviceStatusDecommisioned

	err = s.devicesRepo.UpdateDevice(ctx, device)
	if err != nil {
		return nil, err
	}

	outputGetDevice, err = s.GetDeviceById(ctx, &api.GetDeviceByIdInput{
		DeviceID: input.DeviceID,
	})
	if err != nil {
		return nil, err
	}

	return &api.DecommisionDeviceOutput{
		Device: outputGetDevice.Device,
	}, nil
}

func (s *devicesService) GetDevices(ctx context.Context, input *api.GetDevicesInput) (*api.GetDevicesOutput, error) {
	totalDevices, devicesSubset, err := s.devicesRepo.SelectDevices(ctx, input.QueryParameters)
	if err != nil {
		return nil, err
	}

	checkedDevices := make([]api.Device, 0)
	// Apply Device Check
	for _, device := range devicesSubset {
		checkOutput, err := s.CheckAndUpdateDeviceStatus(ctx, &api.CheckAndUpdateDeviceStatusInput{
			DeviceID: device.ID,
		})
		if err != nil {
			return nil, err
		}

		checkedDevices = append(checkedDevices, checkOutput.Device)
	}

	return &api.GetDevicesOutput{
		TotalDevices: totalDevices,
		Devices:      checkedDevices,
	}, nil
}

func (s *devicesService) GetDeviceById(ctx context.Context, input *api.GetDeviceByIdInput) (*api.GetDeviceByIdOutput, error) {
	device, err := s.devicesRepo.SelectDeviceById(ctx, input.DeviceID)
	if err != nil {
		return nil, err
	}

	return &api.GetDeviceByIdOutput{
		Device: *device,
	}, nil
}

func (s *devicesService) AddDeviceSlot(ctx context.Context, input *api.AddDeviceSlotInput) (*api.AddDeviceSlotOutput, error) {
	outputGetDevice, err := s.GetDeviceById(ctx, &api.GetDeviceByIdInput{
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
			Status:       api.CertificateStatusActive,
			RevocationTimestamp: pq.NullTime{
				Valid: false,
				Time:  time.Time{},
			},
		},
		ArchiveCertificates: []*api.Certificate{},
	})

	err = s.devicesRepo.UpdateDevice(ctx, device)

	if err != nil {
		return nil, err
	}

	outputGetDevice, err = s.GetDeviceById(ctx, &api.GetDeviceByIdInput{
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

func (s *devicesService) UpdateActiveCertificateStatus(ctx context.Context, input *api.UpdateActiveCertificateStatusInput) (*api.UpdateActiveCertificateStatusOutput, error) {
	slot, err := s.devicesRepo.SelectSlotByID(ctx, input.DeviceID, input.SlotID)

	if err != nil {
		return nil, err
	}

	if slot.ActiveCertificate == nil {
		return nil, errors.New("no active certificate found")
	}

	if input.Status == api.CertificateStatusRevoked {
		output, err := s.RevokeActiveCertificate(ctx, &api.RevokeActiveCertificateInput{
			DeviceID:         input.DeviceID,
			RevocationReason: input.RevocationReason,
		})
		if err != nil {
			return nil, err
		}
		return &api.UpdateActiveCertificateStatusOutput{
			Slot: output.Slot,
		}, nil
	} else if input.Status == api.CertificateStatusExpired {
		slot.ActiveCertificate.Status = input.Status
		slot.ArchiveCertificates = append(slot.ArchiveCertificates, slot.ActiveCertificate)
		slot.ActiveCertificate = nil
	} else {
		slot.ActiveCertificate.Status = input.Status
	}

	err = s.devicesRepo.UpdateSlot(ctx, input.DeviceID, *slot)
	if err != nil {
		return nil, err
	}

	slot, err = s.devicesRepo.SelectSlotByID(ctx, input.DeviceID, input.SlotID)
	if err != nil {
		return nil, err
	}

	return &api.UpdateActiveCertificateStatusOutput{
		Slot: *slot,
	}, nil
}

func (s *devicesService) RotateActiveCertificate(ctx context.Context, input *api.RotateActiveCertificateInput) (*api.RotateActiveCertificateOutput, error) {
	slot, err := s.devicesRepo.SelectSlotByID(ctx, input.DeviceID, input.SlotID)
	if err != nil {
		return nil, err
	}

	if slot.ActiveCertificate == nil {
		return nil, errors.New("no active certificate found")
	}

	revokeOutput, err := s.RevokeActiveCertificate(ctx, &api.RevokeActiveCertificateInput{
		DeviceID:         input.DeviceID,
		SlotID:           input.SlotID,
		RevocationReason: "Certificate is being rotated",
	})
	if err != nil {
		return nil, err
	}

	slot = &revokeOutput.Slot
	slot.ActiveCertificate = &api.Certificate{
		CAName:       input.NewCertificate.Issuer.CommonName,
		SerialNumber: utils.InsertNth(utils.ToHexInt(input.NewCertificate.SerialNumber), 2),
		Certificate:  input.NewCertificate,
		Status:       api.CertificateStatusActive,
		RevocationTimestamp: pq.NullTime{
			Valid: false,
			Time:  time.Time{},
		},
	}

	err = s.devicesRepo.UpdateSlot(ctx, input.DeviceID, *slot)
	if err != nil {
		return nil, err
	}

	slot, err = s.devicesRepo.SelectSlotByID(ctx, input.DeviceID, input.SlotID)
	if err != nil {
		return nil, err
	}

	return &api.RotateActiveCertificateOutput{
		Slot: *slot,
	}, nil
}

func (s *devicesService) RevokeActiveCertificate(ctx context.Context, input *api.RevokeActiveCertificateInput) (*api.RevokeActiveCertificateOutput, error) {
	slot, err := s.devicesRepo.SelectSlotByID(ctx, input.DeviceID, input.SlotID)

	if err != nil {
		return &api.RevokeActiveCertificateOutput{}, err
	}

	if slot.ActiveCertificate == nil {
		return &api.RevokeActiveCertificateOutput{}, errors.New("no active certificate found")
	}

	if slot.ActiveCertificate.Status == api.CertificateStatusRevoked {
		return &api.RevokeActiveCertificateOutput{}, errors.New("certificate is already revoked")
	}

	if slot.ActiveCertificate.Status == api.CertificateStatusExpired {
		return &api.RevokeActiveCertificateOutput{}, errors.New("certificate is expired")
	}

	revokeOutput, err := s.caClient.RevokeCertificate(ctx, &caApi.RevokeCertificateInput{
		CAType:                  caApi.CATypePKI,
		CAName:                  slot.ActiveCertificate.CAName,
		CertificateSerialNumber: slot.ActiveCertificate.SerialNumber,
		RevocationReason:        input.RevocationReason,
	})

	if err != nil {
		return &api.RevokeActiveCertificateOutput{}, err
	}

	slot.ActiveCertificate.Status = api.CertificateStatusRevoked
	slot.ActiveCertificate.RevocationReason = input.RevocationReason
	slot.ActiveCertificate.RevocationTimestamp = revokeOutput.RevocationTimestamp

	slot.ArchiveCertificates = append(slot.ArchiveCertificates, slot.ActiveCertificate)
	slot.ActiveCertificate = nil

	s.devicesRepo.UpdateSlot(ctx, input.DeviceID, *slot)
	if err != nil {
		return &api.RevokeActiveCertificateOutput{}, err
	}

	slot, err = s.devicesRepo.SelectSlotByID(ctx, input.DeviceID, input.SlotID)
	if err != nil {
		return &api.RevokeActiveCertificateOutput{}, err
	}

	return &api.RevokeActiveCertificateOutput{
		Slot: *slot,
	}, nil
}

func (s *devicesService) CheckAndUpdateDeviceStatus(ctx context.Context, input *api.CheckAndUpdateDeviceStatusInput) (*api.CheckAndUpdateDeviceStatusOutput, error) {
	return &api.CheckAndUpdateDeviceStatusOutput{}, nil
}

func (s *devicesService) IterateDevicesWithPredicate(ctx context.Context, input *api.IterateDevicesWithPredicateInput) (*api.IterateDevicesWithPredicateOutput, error) {
	output := api.IterateDevicesWithPredicateOutput{}

	var devices []api.Device
	limit := 100
	i := 0

	for {
		devicesOutput, err := s.GetDevices(ctx, &api.GetDevicesInput{
			QueryParameters: common.QueryParameters{
				Pagination: common.PaginationOptions{
					Limit:  limit,
					Offset: i * limit,
				},
			},
		})
		if err != nil {
			return &output, err
		}
		if len(devicesOutput.Devices) == 0 {
			break
		}

		devices = append(devices, devicesOutput.Devices...)
		i++
	}

	for _, v := range devices {
		input.PredicateFunc(&v)
	}

	return &output, nil
}

func (s *devicesService) AddDeviceLog(ctx context.Context, input *api.AddDeviceLogInput) (*api.AddDeviceLogOutput, error) {
	return &api.AddDeviceLogOutput{}, nil
}

func (s *devicesService) GetDeviceLogs(ctx context.Context, input *api.GetDeviceLogsInput) (*api.GetDeviceLogsOutput, error) {
	return &api.GetDeviceLogsOutput{}, nil
}

func (s *devicesService) IsDMSAuthorizedToEnroll(ctx context.Context, input *api.IsDMSAuthorizedToEnrollInput) (*api.IsDMSAuthorizedToEnrollOutput, error) {
	dmsOutput, err := s.dmsManagerClient.GetDMSByName(ctx, &dmsManagerApi.GetDMSByNameInput{
		Name: input.DMSName,
	})
	if err != nil {
		return nil, err
	}

	isAuthorized := slices.Contains(dmsOutput.AuthorizedCAs, input.CAName)

	return &api.IsDMSAuthorizedToEnrollOutput{
		IsAuthorized: isAuthorized,
	}, nil
}

// -------------------------------------------------------------------------------------------------------------------
// 												EST Functions
// -------------------------------------------------------------------------------------------------------------------

func (s *devicesService) CACerts(ctx context.Context, aps string) ([]*x509.Certificate, error) {
	cas := make([]*x509.Certificate, 0)
	s.caClient.IterateCAsWithPredicate(ctx, &caApi.IterateCAsWithPredicateInput{
		CAType: caApi.CATypePKI,
		PredicateFunc: func(c *caApi.CACertificate) {
			cas = append(cas, c.Certificate.Certificate)
		},
	})
	return cas, nil
}

func (s *devicesService) Enroll(ctx context.Context, csr *x509.CertificateRequest, aps string, clientCertificate *x509.Certificate) (*x509.Certificate, error) {
	outGetCA, err := s.caClient.GetCAByName(ctx, &caApi.GetCAByNameInput{
		CAType: caApi.CATypeDMSEnroller,
		CAName: "LAMASSU-DMS-MANAGER",
	})
	if err != nil {
		return nil, err
	}

	err = s.verifyCertificate(clientCertificate, outGetCA.Certificate.Certificate)
	if err != nil {
		return nil, &estErrors.GenericError{
			Message:    "client certificate is not valid: " + err.Error(),
			StatusCode: 403,
		}
	}

	isAuthroizedOutput, err := s.IsDMSAuthorizedToEnroll(ctx, &api.IsDMSAuthorizedToEnrollInput{
		DMSName: clientCertificate.Subject.CommonName,
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
		deviceID = splitedCsrCommonName[1]
	} else {
		return nil, &estErrors.GenericError{
			Message:    "invalid common name format",
			StatusCode: 400,
		}
	}

	getDevice, err := s.GetDeviceById(ctx, &api.GetDeviceByIdInput{
		DeviceID: deviceID,
	})

	if err != nil {
		if _, ok := err.(*deviceErrors.ResourceNotFoundError); !ok {
			return nil, err
		}
		_, err = s.CreateDevice(ctx, &api.CreateDeviceInput{
			DeviceID:    deviceID,
			Alias:       "",
			Tags:        []string{},
			IconColor:   "#0068D1",
			IconName:    "Cg/CgSmartphoneChip",
			Description: "",
		})
		if err != nil {
			return nil, err
		}
	} else {
		for _, slot := range getDevice.Device.Slots {
			if slot.ID == slotID && slot.ActiveCertificate != nil && slot.ActiveCertificate.Status != api.CertificateStatusPendingEnrollment {
				return nil, &estErrors.GenericError{
					Message:    "slot is already enrolled",
					StatusCode: 409,
				}
			}
		}
	}

	signOutput, err := s.caClient.SignCertificateRequest(ctx, &caApi.SignCertificateRequestInput{
		CAType:                    caApi.CATypePKI,
		CertificateSigningRequest: csr,
		CAName:                    aps,
		SignVerbatim:              true,
	})
	if err != nil {
		return nil, err
	}

	_, err = s.AddDeviceSlot(ctx, &api.AddDeviceSlotInput{
		DeviceID:          deviceID,
		SlotID:            slotID,
		ActiveCertificate: signOutput.Certificate,
	})
	if err != nil {
		return nil, err
	}

	return signOutput.Certificate, nil
}

func (s *devicesService) Reenroll(ctx context.Context, cert *x509.Certificate, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	outGetCA, err := s.caClient.GetCAByName(ctx, &caApi.GetCAByNameInput{
		CAType: caApi.CATypePKI,
		CAName: aps,
	})
	if err != nil {
		return nil, err
	}

	err = s.verifyCertificate(cert, outGetCA.Certificate.Certificate)
	if err != nil {
		return nil, err
	}

	if int(time.Until(cert.NotAfter).Hours())*24 > s.minimumReenrollmentDays {
		return nil, &estErrors.GenericError{
			Message:    "certificate can only be renewed" + fmt.Sprintf("%d", s.minimumReenrollmentDays) + " days before expiration",
			StatusCode: 403,
		}
	}

	if !reflect.DeepEqual(csr.Subject, cert.Subject) {
		return nil, &estErrors.GenericError{
			Message:    "CSR subject does not match certificate subject",
			StatusCode: 400,
		}
	}

	signOutput, err := s.caClient.SignCertificateRequest(ctx, &caApi.SignCertificateRequestInput{
		CAType:                    caApi.CATypePKI,
		CertificateSigningRequest: csr,
		CAName:                    aps,
		SignVerbatim:              true,
	})
	if err != nil {
		return nil, err
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
		deviceID = splitedCsrCommonName[1]
	} else {
		return nil, &estErrors.GenericError{
			Message:    "invalid common name format",
			StatusCode: 400,
		}
	}

	_, err = s.RotateActiveCertificate(ctx, &api.RotateActiveCertificateInput{
		DeviceID:       deviceID,
		SlotID:         slotID,
		NewCertificate: signOutput.Certificate,
	})
	if err != nil {
		return nil, err
	}

	return signOutput.Certificate, nil
}

func (s *devicesService) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, aps string, cert *x509.Certificate) (*x509.Certificate, []byte, error) {
	csrkey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	privkey, err := x509.MarshalPKCS8PrivateKey(csrkey)
	if err != nil {
		return nil, nil, err
	}

	csr, err = s.generateCSR(csr, csrkey)
	if err != nil {
		return nil, nil, err
	}

	crt, err := s.Enroll(ctx, csr, aps, cert)
	if err != nil {
		return nil, nil, err
	}

	return crt, privkey, nil
}

// -------------------------------------------------------------------------------------------------------------------
// 													UTILS
// -------------------------------------------------------------------------------------------------------------------

func (s *devicesService) verifyCertificate(clientCertificate *x509.Certificate, caCertificate *x509.Certificate) error {
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(caCertificate)

	opts := x509.VerifyOptions{
		Roots:     clientCAs,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	_, err := clientCertificate.Verify(opts)

	if err != nil {
		return errors.New("could not verify client certificate: " + err.Error())
	}

	return nil
}

func (s *devicesService) generateCSR(csr *x509.CertificateRequest, key interface{}) (*x509.CertificateRequest, error) {
	subj := csr.Subject

	rawSubject := subj.ToRDNSequence()
	asn1Subj, _ := asn1.Marshal(rawSubject)
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		SignatureAlgorithm: x509.ECDSAWithSHA512,
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %v", err)
	}

	csrNew, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate request: %v", err)
	}
	return csrNew, nil
}
