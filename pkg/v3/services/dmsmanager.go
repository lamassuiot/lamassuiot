package services

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/v3/errs"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/storage"
	"github.com/sirupsen/logrus"
)

var lDMS *logrus.Entry

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
}

type DMSManagerBuilder struct {
	Logger        *logrus.Entry
	DevManagerCli DeviceManagerService
	CAClient      CAService
	DMSStorage    storage.DMSRepo
}

func NewDMSManagerService(builder DMSManagerBuilder) DMSManagerService {
	lDMS = builder.Logger

	return &DmsManagerServiceImpl{
		dmsStorage:       builder.DMSStorage,
		caClient:         builder.CAClient,
		deviceManagerCli: builder.DevManagerCli,
	}
}

func (svc *DmsManagerServiceImpl) SetService(service DMSManagerService) {
	svc.service = service
}

type CreateDMSInput struct {
	ID              string
	Name            string
	Metadata        map[string]string
	IdentityProfile models.IdentityProfile
}

type RemoteAccessIdentityInput struct {
	Csr     *models.X509CertificateRequest
	Subject *models.Subject
}

func (svc DmsManagerServiceImpl) CreateDMS(input CreateDMSInput) (*models.DMS, error) {
	lLocal := lDMS.WithField("method", "Create DMS")
	lLocal.Debugf("checking if DMS '%s' exists", input.ID)
	if exists, _, err := svc.dmsStorage.SelectExists(context.Background(), input.ID); err != nil {
		lLocal.Errorf("something went wrong while checking if DMS '%s' exists in storage engine: %s", input.ID, err)
		return nil, err
	} else if exists {
		lLocal.Errorf("DMS '%s' does not exist in storage engine", input.ID)
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

	dms, err := svc.dmsStorage.Insert(context.Background(), dms)
	if err != nil {
		lLocal.Errorf("could not insert DMS '%s': %s", dms.ID, err)
		return nil, err
	}
	lLocal.Debugf("DMS '%s' persisted into storage engine", dms.ID)

	return dms, nil
}

type UpdateIdentityProfileInput struct {
	ID                 string
	NewIdentityProfile models.IdentityProfile
}

func (svc DmsManagerServiceImpl) UpdateIdentityProfile(input UpdateIdentityProfileInput) (*models.DMS, error) {
	exists, dms, err := svc.dmsStorage.SelectExists(context.Background(), input.ID)
	if err != nil {
		return nil, err
	} else if !exists {
		return nil, errs.ErrDMSNotFound
	}

	dms.IdentityProfile = input.NewIdentityProfile

	return svc.dmsStorage.Update(context.Background(), dms)
}

type GetDMSByIDInput struct {
	ID string
}

func (svc DmsManagerServiceImpl) GetDMSByID(input GetDMSByIDInput) (*models.DMS, error) {
	exists, dms, err := svc.dmsStorage.SelectExists(context.Background(), input.ID)
	if err != nil {
		return nil, err
	} else if !exists {
		return nil, errs.ErrDMSNotFound
	}

	return dms, nil
}

type GetAllInput struct {
	ListInput[models.DMS]
}

func (svc DmsManagerServiceImpl) GetAll(input GetAllInput) (string, error) {
	bookmark, err := svc.dmsStorage.SelectAll(context.Background(), input.ExhaustiveRun, input.ApplyFunc, input.QueryParameters, nil)
	if err != nil {
		return "", err
	}

	return bookmark, nil
}

func (svc DmsManagerServiceImpl) CACerts(aps string) ([]*x509.Certificate, error) {
	cas := []*x509.Certificate{}

	exists, dms, err := svc.dmsStorage.SelectExists(context.Background(), aps)
	if err != nil {
		return nil, err
	} else if exists {
		return nil, errs.ErrDMSAlreadyExists
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
		caResponse, err := svc.caClient.GetCAByID(GetCAByIDInput{
			CAID: ca,
		})
		if err != nil {
			return nil, err
		}

		cas = append(cas, (*x509.Certificate)(caResponse.Certificate.Certificate))
	}

	return cas, nil
}

// Validation:
//   - Cert:
//     Only Bootstrap cert (CA issued By Lamassu)
func (svc DmsManagerServiceImpl) Enroll(authMode models.ESTAuthMode, authOptions interface{}, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
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
	if estAuthOptions.AuthMode != authMode {
		lDMS.Errorf("aborting enrollment process for device '%s'. DMS '%s' doesn't support '%s' authentication mechanism. Should use '%s' instead", csr.Subject.CommonName, dms.ID, authMode, estAuthOptions.AuthMode)
		return nil, errs.ErrDMSInvalidAuthMode
	}

	if authMode != models.MutualTLS {
		lDMS.Errorf("aborting enrollment process for device '%s'. Currently only mTLS auth mode is allowed. DMS '%s' is configured with '%s'", csr.Subject.CommonName, dms.ID, estAuthOptions.AuthMode)
		return nil, errs.ErrDMSAuthModeNotSupported
	}

	var clientCert *x509.Certificate
	switch t := authOptions.(type) {
	case models.ESTServerAuthOptionsMutualTLS:
		clientCert = t.ClientCertificate
	default:
		return nil, fmt.Errorf("unsupported auth mode. Provided auth options are of type %s", t)
	}

	lDMS.Debugf("presented client certificate has CommonName '%s' and SerialNumber '%s' issued by CA with CommonName '%s'", clientCert.Subject.CommonName, helpers.SerialNumberToString(clientCert.SerialNumber), clientCert.Issuer.CommonName)

	//check if certificate is a certificate issued by bootstrap CA
	validCertificate := false
	estEnrollOpts := dms.IdentityProfile.EnrollmentSettings.EnrollmentOptionsESTRFC7030
	for _, caID := range estEnrollOpts.AuthOptionsMTLS.ValidationCAs {
		ca, err := svc.caClient.GetCAByID(GetCAByIDInput{CAID: caID})
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
		lDMS.Errorf("invalid enrollment. Used certificate not authorized for this DMS. Certificate has SerialNumber %s issued by CA %s", helpers.SerialNumberToString(clientCert.SerialNumber), clientCert.Issuer.CommonName)
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
			lDMS.Debugf("DMS '%s' allows new enrollments. Continuing enrollment process for device '%s'", dms.ID, csr.Subject.CommonName)
		} else {
			lDMS.Debugf("DMS '%s' forbids new enrollments. Aborting enrollment process for device '%s'. Consider switching NewEnrollment option ON in the DMS", dms.ID, csr.Subject.CommonName)
			return nil, fmt.Errorf("forbiddenNewEnrollment")
		}
	}

	if dms.IdentityProfile.EnrollmentSettings.JustInTime {
		if device == nil {
			lDMS.Debugf("DMS '%s' is configured with JustInTime registration. Will create device with ID %s", dms.ID, csr.Subject.CommonName)
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
		lDMS.Errorf("DMS '%s' is doesn't allow JustInTime registration. Register the '%s' device or switch DMS JIT option ON", dms.ID, csr.Subject.CommonName)
		return nil, fmt.Errorf("device not preregistered")
	} else {
		lDMS.Debugf("device '%s' is preregistered. Continuing enrollment process", device.ID)
	}

	crt, err := svc.caClient.SignCertificate(SignCertificateInput{
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
		lDMS.Errorf("could not update device '%s' identity slot. Aborting enrollment process: %s", device.ID, err)
		return nil, err
	}

	return (*x509.Certificate)(crt.Certificate), nil

}

func (svc DmsManagerServiceImpl) Reenroll(authMode models.ESTAuthMode, authOptions interface{}, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	return nil, fmt.Errorf("TODO")
}

func (svc DmsManagerServiceImpl) ServerKeyGen(authMode models.ESTAuthMode, authOptions interface{}, csr *x509.CertificateRequest, aps string) (*x509.Certificate, interface{}, error) {
	return nil, nil, fmt.Errorf("TODO")
}
