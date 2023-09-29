package services

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/errs"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/resources"
	"github.com/lamassuiot/lamassuiot/pkg/v3/storage"
	"github.com/robfig/cron/v3"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
)

var lDMS *logrus.Entry
var dmsValidate *validator.Validate
var localRegAuthCA = "lms.lra"

type DMSManagerService interface {
	ESTService
	CreateDMS(input CreateDMSInput) (*models.DMS, error)
	UpdateIdentityProfile(input UpdateIdentityProfileInput) (*models.DMS, error)
	GetDMSByID(input GetDMSByIDInput) (*models.DMS, error)
	GetAll(input GetAllInput) (string, error)
}

type DmsManagerServiceImpl struct {
	service          DMSManagerService
	downstreamCert   *x509.Certificate
	deviceManagerCli DeviceManagerService
	dmsStorage       storage.DMSRepo
	caClient         CAService
	cronInstance     *cron.Cron
}

type DMSManagerBuilder struct {
	Logger              *logrus.Entry
	DevManagerCli       DeviceManagerService
	CAClient            CAService
	DMSStorage          storage.DMSRepo
	DeviceMonitorConfig config.DeviceMonitorConfig
}

func NewDMSManagerService(builder DMSManagerBuilder) DMSManagerService {
	lDMS = builder.Logger
	dmsValidate = validator.New()

	ctx := context.Background()
	lFunc := helpers.ConfigureLoggerWithRequestID(ctx, lDMS)

	svc := &DmsManagerServiceImpl{
		dmsStorage:       builder.DMSStorage,
		caClient:         builder.CAClient,
		deviceManagerCli: builder.DevManagerCli,
		cronInstance:     cron.New(),
	}

	caExists := false
	_, err := svc.caClient.GetCAsByCommonName(ctx, GetCAsByCommonNameInput{
		CommonName:    localRegAuthCA,
		ExhaustiveRun: false,
		ApplyFunc: func(cert *models.CACertificate) {
			caExists = true
		},
	})
	if err != nil {
		lFunc.Fatalf("could not initialize service: could not check if internal CA '%s' exists: %s", localRegAuthCA, err)
	}

	if !caExists {
		caDur, _ := models.ParseDuration("50y")
		issuanceDur, _ := models.ParseDuration("3y")
		_, err := svc.caClient.CreateCA(ctx, CreateCAInput{
			KeyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.ECDSA),
				Bits: 256,
			},
			Subject: models.Subject{
				CommonName:       string(localRegAuthCA),
				Organization:     "LAMASSU",
				OrganizationUnit: "INTERNAL CA",
			},
			CAExpiration: models.Expiration{
				Type:     models.Duration,
				Duration: (*models.TimeDuration)(&caDur),
			},
			IssuanceExpiration: models.Expiration{
				Type:     models.Duration,
				Duration: (*models.TimeDuration)(&issuanceDur),
			},
		})

		if err != nil {
			lFunc.Fatalf("could not initialize service: could not create internal CA '%s': %s", localRegAuthCA, err)
		}
	}

	deviceMonitor := func() {
		_, err = svc.GetAll(GetAllInput{
			ListInput[models.DMS]{
				QueryParameters: &resources.QueryParameters{},
				ExhaustiveRun:   true,
				ApplyFunc: func(dms *models.DMS) {
					svc.deviceManagerCli.GetDeviceByDMS(GetDevicesByDMSInput{
						DMSID: dms.ID,
						ListInput: ListInput[models.Device]{
							QueryParameters: &resources.QueryParameters{},
							ExhaustiveRun:   true,
							ApplyFunc: func(device *models.Device) {
								//TODO: comprobar vs los deltas de Preventive y Critical
							},
						},
					})
				},
			},
		})
	}

	deviceMonitor()

	if builder.DeviceMonitorConfig.Enabled {
		_, err := svc.cronInstance.AddFunc(builder.DeviceMonitorConfig.Frequency, deviceMonitor)
		if err != nil {
			lCA.Errorf("could not add scheduled run for checking devices")
		}

		svc.cronInstance.Start()
	}

	return svc
}

func (svc *DmsManagerServiceImpl) SetService(service DMSManagerService) {
	svc.service = service
}

type CreateDMSInput struct {
	ID              string `validate:"required"`
	Name            string `validate:"required"`
	Metadata        map[string]string
	IdentityProfile models.IdentityProfile `validate:"required"`
}

func (svc DmsManagerServiceImpl) CreateDMS(input CreateDMSInput) (*models.DMS, error) {
	err := dmsValidate.Struct(input)
	if err != nil {
		lDMS.Errorf("struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}
	lDMS.Debugf("checking if DMS '%s' exists", input.ID)
	if exists, _, err := svc.dmsStorage.SelectExists(context.Background(), input.ID); err != nil {
		lDMS.Errorf("something went wrong while checking if DMS '%s' exists in storage engine: %s", input.ID, err)
		return nil, err
	} else if exists {
		lDMS.Errorf("DMS '%s' already exist in storage engine", input.ID)
		return nil, errs.ErrDMSAlreadyExists
	}

	now := time.Now()

	dms := &models.DMS{
		ID:              input.ID,
		Name:            input.Name,
		Metadata:        input.Metadata,
		CreationDate:    now,
		IdentityProfile: input.IdentityProfile,
	}

	dms, err = svc.dmsStorage.Insert(context.Background(), dms)
	if err != nil {
		lDMS.Errorf("could not insert DMS '%s': %s", dms.ID, err)
		return nil, err
	}
	lDMS.Debugf("DMS '%s' persisted into storage engine", dms.ID)

	return dms, nil
}

type UpdateIdentityProfileInput struct {
	ID                 string                 `validate:"required"`
	NewIdentityProfile models.IdentityProfile `validate:"required"`
}

func (svc DmsManagerServiceImpl) UpdateIdentityProfile(input UpdateIdentityProfileInput) (*models.DMS, error) {

	err := dmsValidate.Struct(input)
	if err != nil {
		lDMS.Errorf("struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}
	lDMS.Debugf("checking if DMS '%s' exists", input.ID)
	exists, dms, err := svc.dmsStorage.SelectExists(context.Background(), input.ID)
	if err != nil {
		lDMS.Errorf("something went wrong while checking if DMS '%s' exists in storage engine: %s", input.ID, err)
		return nil, err
	} else if !exists {
		lDMS.Errorf("DMS '%s' does not exist in storage engine", input.ID)
		return nil, errs.ErrDMSNotFound
	}

	dms.IdentityProfile = input.NewIdentityProfile
	lDMS.Debugf("updating DMS %s identity profile", input.ID)
	return svc.dmsStorage.Update(context.Background(), dms)
}

type GetDMSByIDInput struct {
	ID string `validate:"required"`
}

func (svc DmsManagerServiceImpl) GetDMSByID(input GetDMSByIDInput) (*models.DMS, error) {

	err := dmsValidate.Struct(input)
	if err != nil {
		lDMS.Errorf("struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}
	lDMS.Debugf("checking if DMS '%s' exists", input.ID)
	exists, dms, err := svc.dmsStorage.SelectExists(context.Background(), input.ID)
	if err != nil {
		lDMS.Errorf("something went wrong while checking if DMS '%s' exists in storage engine: %s", input.ID, err)
		return nil, err
	} else if !exists {
		lDMS.Errorf("DMS '%s' does not exist in storage engine", input.ID)
		return nil, errs.ErrDMSNotFound
	}
	lDMS.Debugf("read DMS %s", dms.ID)

	return dms, nil
}

type GetAllInput struct {
	ListInput[models.DMS]
}

func (svc DmsManagerServiceImpl) GetAll(input GetAllInput) (string, error) {
	lDMS.Debugf("reading all DMSs")
	bookmark, err := svc.dmsStorage.SelectAll(context.Background(), input.ExhaustiveRun, input.ApplyFunc, input.QueryParameters, nil)
	if err != nil {
		lDMS.Errorf("something went wrong while reading all DMSs from storage engine: %s", err)
		return "", err
	}

	return bookmark, nil
}

func (svc DmsManagerServiceImpl) CACerts(aps string) ([]*x509.Certificate, error) {
	cas := []*x509.Certificate{}
	lDMS.Debugf("checking if DMS '%s' exists", aps)
	exists, dms, err := svc.dmsStorage.SelectExists(context.Background(), aps)
	if err != nil {
		lDMS.Errorf("something went wrong while checking if DMS '%s' exists in storage engine: %s", aps, err)
		return nil, err
	} else if !exists {
		lDMS.Errorf("DMS '%s' does not exist in storage engine", aps)
		return nil, errs.ErrDMSNotFound
	}

	caDistribSettings := dms.IdentityProfile.CADistributionSettings

	if caDistribSettings.IncludeLamassuSystemCA {
		cas = append(cas, svc.downstreamCert)
	}

	reqCAs := []string{}
	reqCAs = append(reqCAs, dms.IdentityProfile.CADistributionSettings.ManagedCAs...)

	if caDistribSettings.IncludeAuthorizedCA {
		reqCAs = append(reqCAs, dms.IdentityProfile.EnrollmentSettings.AuthorizedCA)
	}

	for _, ca := range reqCAs {
		lDMS.Debugf("Reading CA %s Certificate", ca)
		caResponse, err := svc.caClient.GetCAByID(context.Background(), GetCAByIDInput{
			CAID: ca,
		})
		if err != nil {
			lDMS.Errorf("something went wrong while reading CA '%s' by ID: %s", ca, err)
			return nil, err
		}

		cas = append(cas, (*x509.Certificate)(caResponse.Certificate.Certificate))
	}

	lDMS.Debugf("Read certificates of the CAs associated with the DMS %s", aps)
	return cas, nil
}

// Validation:
//   - Cert:
//     Only Bootstrap cert (CA issued By Lamassu)
func (svc DmsManagerServiceImpl) Enroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	lDMS.Debugf("checking if DMS '%s' exists", aps)
	dms, err := svc.GetDMSByID(GetDMSByIDInput{
		ID: aps,
	})
	if err != nil {
		lDMS.Errorf("aborting enrollment process for device '%s'. Could not get DMS '%s': %s", csr.Subject.CommonName, aps, err)
		return nil, errs.ErrDMSNotFound
	}

	if dms.IdentityProfile.EnrollmentSettings.EnrollmentProtocol != models.EST {
		lDMS.Errorf("aborting enrollment process for device '%s'. DMS '%s' doesn't support EST Protocol", csr.Subject.CommonName, aps)
		return nil, errs.ErrDMSOnlyEST
	}

	estAuthOptions := dms.IdentityProfile.EnrollmentSettings.EnrollmentOptionsESTRFC7030
	clientCert, hasValue := ctx.Value(models.ESTAuthModeMutualTLS).(*x509.Certificate)
	if !hasValue {
		lDMS.Errorf("aborting enrollment process for device '%s'. Currently only mTLS auth mode is allowed. DMS '%s' is configured with '%s'. No client certificate was presented", csr.Subject.CommonName, dms.ID, estAuthOptions.AuthMode)
		return nil, errs.ErrDMSAuthModeNotSupported
	}

	lDMS.Debugf("presented client certificate has CommonName '%s' and SerialNumber '%s' issued by CA with CommonName '%s'", clientCert.Subject.CommonName, helpers.SerialNumberToString(clientCert.SerialNumber), clientCert.Issuer.CommonName)

	//check if certificate is a certificate issued by bootstrap CA
	validCertificate := false
	estEnrollOpts := dms.IdentityProfile.EnrollmentSettings.EnrollmentOptionsESTRFC7030
	for _, caID := range estEnrollOpts.AuthOptionsMTLS.ValidationCAs {
		ca, err := svc.caClient.GetCAByID(context.Background(), GetCAByIDInput{CAID: caID})
		if err != nil {
			lDMS.Warnf("could not obtain lamassu CA '%s'. Skipping to next validation CA: %s", caID, err)
			continue
		}

		err = helpers.ValidateCertificate((*x509.Certificate)(ca.Certificate.Certificate), *clientCert)
		if err != nil {
			lDMS.Debugf("invalid validation using CA [%s] with CommonName '%s', SerialNumber '%s'", ca.ID, ca.Subject.CommonName, ca.SerialNumber)
		} else {
			lDMS.Debugf("OK validation using CA [%s] with CommonName '%s', SerialNumber '%s'", ca.ID, ca.Subject.CommonName, ca.SerialNumber)
			validCertificate = true
			break
		}
	}

	if !validCertificate {
		lDMS.Errorf("invalid enrollment. used certificate not authorized for this DMS. certificate has SerialNumber %s issued by CA %s", helpers.SerialNumberToString(clientCert.SerialNumber), clientCert.Issuer.CommonName)
		return nil, errs.ErrDMSEnrollInvalidCert
	}

	var device *models.Device
	device, err = svc.deviceManagerCli.GetDeviceByID(GetDeviceByIDInput{
		ID: csr.Subject.CommonName,
	})
	if err != nil {
		switch err {
		case errs.ErrDeviceNotFound:
			lDMS.Debugf("device '%s' doesn't exist", csr.Subject.CommonName)
		default:
			lDMS.Errorf("could not get device '%s': %s", csr.Subject.CommonName, err)
			return nil, err
		}
	} else {
		lDMS.Debugf("device '%s' does exist", csr.Subject.CommonName)
		if dms.IdentityProfile.EnrollmentSettings.AllowNewEnrollment {
			lDMS.Debugf("DMS '%s' allows new enrollments. continuing enrollment process for device '%s'", dms.ID, csr.Subject.CommonName)
		} else {
			lDMS.Debugf("DMS '%s' forbids new enrollments. aborting enrollment process for device '%s'. consider switching NewEnrollment option ON in the DMS", dms.ID, csr.Subject.CommonName)
			return nil, fmt.Errorf("forbiddenNewEnrollment")
		}
	}

	if dms.IdentityProfile.EnrollmentSettings.JustInTime {
		if device == nil {
			lDMS.Debugf("DMS '%s' is configured with JustInTime registration. will create device with ID %s", dms.ID, csr.Subject.CommonName)
			//contact device manager and register device first
			device, err = svc.deviceManagerCli.CreateDevice(CreateDeviceInput{
				ID:        csr.Subject.CommonName,
				Alias:     csr.Subject.CommonName,
				Tags:      dms.IdentityProfile.EnrollmentSettings.DeviceProvisionSettings.Tags,
				Metadata:  dms.IdentityProfile.EnrollmentSettings.DeviceProvisionSettings.Metadata,
				Icon:      dms.IdentityProfile.EnrollmentSettings.DeviceProvisionSettings.Icon,
				IconColor: dms.IdentityProfile.EnrollmentSettings.DeviceProvisionSettings.IconColor,
				DMSID:     dms.ID,
			})
			if err != nil {
				lDMS.Errorf("could not register device '%s': %s", csr.Subject.CommonName, err)
				return nil, err
			}
		} else {
			lDMS.Debugf("skipping '%s' device registration since already exists", csr.Subject.CommonName)
		}
	} else if device == nil {
		lDMS.Errorf("DMS '%s' is doesn't allow JustInTime registration. register the '%s' device or switch DMS JIT option ON", dms.ID, csr.Subject.CommonName)
		return nil, fmt.Errorf("device not preregistered")
	} else {
		lDMS.Debugf("device '%s' is preregistered. continuing enrollment process", device.ID)
	}

	crt, err := svc.caClient.SignCertificate(context.Background(), SignCertificateInput{
		CAID:         dms.IdentityProfile.EnrollmentSettings.AuthorizedCA,
		CertRequest:  (*models.X509CertificateRequest)(csr),
		Subject:      nil,
		SignVerbatim: true,
	})
	if err != nil {
		lDMS.Errorf("could issue certificate for device '%s': %s", csr.Subject.CommonName, err)
		return nil, err
	}

	var idSlot models.Slot[models.Certificate]
	if device.IdentitySlot == nil {
		idSlot = models.Slot[models.Certificate]{
			Status:        models.SlotActive,
			ActiveVersion: 0,
			SecretType:    models.X509SlotProfileType,
			Secrets: map[int]models.Certificate{
				0: *crt,
			},
			Logs: map[time.Time]models.LogMsg{},
		}
	} else {
		idSlot = *device.IdentitySlot
		idSlot.ActiveVersion = idSlot.ActiveVersion + 1
		idSlot.Status = models.SlotActive
		idSlot.Secrets[idSlot.ActiveVersion] = *crt
	}

	idSlot.Logs[time.Now()] = models.LogMsg{
		Msg:         fmt.Sprintf("Enrolled Device with Certificate with Serial Number %s", crt.SerialNumber),
		Criticality: models.InfoCriticality,
	}

	_, err = svc.deviceManagerCli.UpdateIdentitySlot(UpdateIdentitySlotInput{
		ID:   csr.Subject.CommonName,
		Slot: idSlot,
	})
	if err != nil {
		lDMS.Errorf("could not update device '%s' identity slot. aborting enrollment process: %s", device.ID, err)
		return nil, err
	}

	return (*x509.Certificate)(crt.Certificate), nil

}
func (svc DmsManagerServiceImpl) Reenroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	lDMS.Debugf("checking if DMS '%s' exists", aps)
	dms, err := svc.GetDMSByID(GetDMSByIDInput{
		ID: aps,
	})
	if err != nil {
		lDMS.Errorf("aborting reenrollment process for device '%s'. Could not get DMS '%s': %s", csr.Subject.CommonName, aps, err)
		return nil, errs.ErrDMSNotFound
	}

	if dms.IdentityProfile.EnrollmentSettings.EnrollmentProtocol != models.EST {
		lDMS.Errorf("aborting reenrollment process for device '%s'. DMS '%s' doesn't support EST Protocol", csr.Subject.CommonName, aps)
		return nil, errs.ErrDMSOnlyEST
	}

	estAuthOptions := dms.IdentityProfile.EnrollmentSettings.EnrollmentOptionsESTRFC7030
	clientCert, hasValue := ctx.Value(models.ESTAuthModeMutualTLS).(*x509.Certificate)
	if !hasValue {
		lDMS.Errorf("aborting enrollment process for device '%s'. currently only mTLS auth mode is allowed. DMS '%s' is configured with '%s'. No client certificate was presented", csr.Subject.CommonName, dms.ID, estAuthOptions.AuthMode)
		return nil, errs.ErrDMSAuthModeNotSupported
	}

	lDMS.Debugf("presented client certificate has CN=%s and SN=%s issued by CA with CommonName '%s'", clientCert.Subject.CommonName, helpers.SerialNumberToString(clientCert.SerialNumber), clientCert.Issuer.CommonName)

	enrollCAID := dms.IdentityProfile.EnrollmentSettings.AuthorizedCA
	enrollCA, err := svc.caClient.GetCAByID(context.Background(), GetCAByIDInput{
		CAID: enrollCAID,
	})
	if err != nil {
		lDMS.Errorf("could not get enroll CA with ID=%s: %s", enrollCAID, err)
		return nil, err
	}

	validCertificate := false
	//check if certificate is a certificate issued by Enroll CA
	lDMS.Debugf("validating client certificate using EST Enrollment CA witch has ID=%s CN=%s SN=%s", enrollCAID, enrollCA.Certificate.Subject.CommonName, enrollCA.SerialNumber)
	err = helpers.ValidateCertificate((*x509.Certificate)(enrollCA.Certificate.Certificate), *clientCert)
	if err != nil {
		lDMS.Warnf("invalid validation using enroll CA")
	} else {
		lDMS.Debugf("OK validation using enroll")
		validCertificate = true
	}

	if !validCertificate {
		estReEnrollOpts := dms.IdentityProfile.ReEnrollmentSettings
		aValCAsCtr := len(estReEnrollOpts.AdditionalValidationCAs)
		lDMS.Debugf("could not validate client certificate using enroll CA. Will try validating using Additional Validation CAs")
		lDMS.Debugf("DMS has %d additonal validation CAs", aValCAsCtr)
		//check if certificate is a certificate issued by Extra Val CAs

		for idx, caID := range estReEnrollOpts.AdditionalValidationCAs {
			lDMS.Debugf("[%d/%d] obtainig validation with ID %s", idx, aValCAsCtr, caID)
			ca, err := svc.caClient.GetCAByID(context.Background(), GetCAByIDInput{CAID: caID})
			if err != nil {
				lDMS.Warnf("[%d/%d] could not obtain lamassu CA with ID %s. Skipping to next validation CA: %s", idx, aValCAsCtr, caID, err)
				continue
			}

			err = helpers.ValidateCertificate((*x509.Certificate)(ca.Certificate.Certificate), *clientCert)
			if err != nil {
				lDMS.Debugf("[%d/%d] invalid validation using CA [%s] with CommonName '%s', SerialNumber '%s'", idx, aValCAsCtr, ca.ID, ca.Subject.CommonName, ca.SerialNumber)
			} else {
				lDMS.Debugf("[%d/%d] OK validation using CA [%s] with CommonName '%s', SerialNumber '%s'", idx, aValCAsCtr, ca.ID, ca.Subject.CommonName, ca.SerialNumber)
				validCertificate = true
				break
			}
		}
	}

	if !validCertificate {
		lDMS.Errorf("invalid reenrollment. Used certificate not authorized for this DMS. Certificate has SerialNumber %s issued by CA with CN=%s", helpers.SerialNumberToString(clientCert.SerialNumber), clientCert.Issuer.CommonName)
		return nil, errs.ErrDMSEnrollInvalidCert
	}

	var device *models.Device
	device, err = svc.deviceManagerCli.GetDeviceByID(GetDeviceByIDInput{
		ID: csr.Subject.CommonName,
	})
	if err != nil {
		switch err {
		case errs.ErrDeviceNotFound:
			lDMS.Debugf("device '%s' doesn't exist", csr.Subject.CommonName)
		default:
			lDMS.Errorf("could not get device '%s': %s", csr.Subject.CommonName, err)
			return nil, err
		}
	} else {
		lDMS.Debugf("device '%s' does exist", csr.Subject.CommonName)
	}

	currentDeviceCert := device.IdentitySlot.Secrets[device.IdentitySlot.ActiveVersion].Certificate
	lDMS.Debugf("device %s ActiveVersion=%d for IdentitySlot is certificate with SN=%s", device.ID, device.IdentitySlot.ActiveVersion, helpers.SerialNumberToString(currentDeviceCert.SerialNumber))

	lDMS.Debugf("checking CSR has same RawSubject as the previous enrollment at byte level. DeviceID=%s ActiveVersion=%d", device.ID, device.IdentitySlot.ActiveVersion)
	if slices.Compare[byte](device.IdentitySlot.Secrets[device.IdentitySlot.ActiveVersion].Certificate.RawSubject, csr.RawSubject) != 0 {
		lDMS.Errorf("incoming CSR for device %s has different RawSubject compared with previous enrollment with ActiveVersion=%d", device.ID, device.IdentitySlot.ActiveVersion)
		return nil, fmt.Errorf("invalid RawSubject bytes")
	}

	now := time.Now()
	lDMS.Debugf("checking if DMS allows enrollment at current delta for device %s", device.ID)

	comparisonTimeThreshold := currentDeviceCert.NotAfter.Add(time.Duration(dms.IdentityProfile.ReEnrollmentSettings.AllowedReenrollmentDelta))
	lDMS.Debugf("current device certificate expires at %s. DMS has a allowance reenroll delta of %s. Current device expiration + allowance delta is %s (delta=%s)", currentDeviceCert.NotAfter.UTC().Format("2006-01-02T15:04:05Z07:00"), dms.IdentityProfile.ReEnrollmentSettings.AllowedReenrollmentDelta.String(), comparisonTimeThreshold.UTC().Format("2006-01-02T15:04:05Z07:00"), models.TimeDuration(now.Sub(comparisonTimeThreshold)).String())

	//Check if current cert is REVOKED

	//Check if Not in DMS ReEnroll Window
	if !comparisonTimeThreshold.After(now) {
		lDMS.Debugf("aborting reenrollment. Device has a valid certificate and DMS reenrollment window does not allow reenrolling with %s delta. Update DMS or wait until the reenrollment window is open", models.TimeDuration(now.Sub(comparisonTimeThreshold)).String())
		return nil, fmt.Errorf("invalid reenroll window")
	}

	//Check if EXPIRED

	crt, err := svc.caClient.SignCertificate(context.Background(), SignCertificateInput{
		CAID:         dms.IdentityProfile.EnrollmentSettings.AuthorizedCA,
		CertRequest:  (*models.X509CertificateRequest)(csr),
		Subject:      nil,
		SignVerbatim: true,
	})
	if err != nil {
		lDMS.Errorf("could issue certificate for device '%s': %s", csr.Subject.CommonName, err)
		return nil, err
	}

	var idSlot models.Slot[models.Certificate]
	idSlot = *device.IdentitySlot
	idSlot.ActiveVersion = idSlot.ActiveVersion + 1
	idSlot.Status = models.SlotActive
	idSlot.Secrets[idSlot.ActiveVersion] = *crt

	idSlot.Logs[time.Now()] = models.LogMsg{
		Msg:         fmt.Sprintf("Re Enrolled Device with Certificate with Serial Number %s", crt.SerialNumber),
		Criticality: models.InfoCriticality,
	}

	_, err = svc.deviceManagerCli.UpdateIdentitySlot(UpdateIdentitySlotInput{
		ID:   csr.Subject.CommonName,
		Slot: idSlot,
	})
	if err != nil {
		lDMS.Errorf("could not update device '%s' identity slot. Aborting enrollment process: %s", device.ID, err)
		return nil, err
	}

	return (*x509.Certificate)(crt.Certificate), nil
}

func (svc DmsManagerServiceImpl) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, interface{}, error) {
	return nil, nil, fmt.Errorf("TODO")
}
