package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	external_clients "github.com/lamassuiot/lamassuiot/v2/pkg/clients/external"
	"github.com/lamassuiot/lamassuiot/v2/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
	"golang.org/x/exp/slices"
)

var lDMS *logrus.Entry
var dmsValidate = validator.New()

type DMSManagerMiddleware func(DMSManagerService) DMSManagerService

type DMSManagerService interface {
	ESTService
	GetDMSStats(ctx context.Context, input GetDMSStatsInput) (*models.DMSStats, error)
	CreateDMS(ctx context.Context, input CreateDMSInput) (*models.DMS, error)
	UpdateDMS(ctx context.Context, input UpdateDMSInput) (*models.DMS, error)
	GetDMSByID(ctx context.Context, input GetDMSByIDInput) (*models.DMS, error)
	GetAll(ctx context.Context, input GetAllInput) (string, error)

	BindIdentityToDevice(ctx context.Context, input BindIdentityToDeviceInput) (*models.BindIdentityToDeviceOutput, error)
}

type DMSManagerServiceImpl struct {
	service          DMSManagerService
	downstreamCert   *x509.Certificate
	dmsStorage       storage.DMSRepo
	deviceManagerCli DeviceManagerService
	caClient         CAService
}

type DMSManagerBuilder struct {
	Logger                *logrus.Entry
	DevManagerCli         DeviceManagerService
	CAClient              CAService
	DMSStorage            storage.DMSRepo
	DownstreamCertificate *x509.Certificate
}

func NewDMSManagerService(builder DMSManagerBuilder) DMSManagerService {
	lDMS = builder.Logger

	svc := &DMSManagerServiceImpl{
		dmsStorage:       builder.DMSStorage,
		caClient:         builder.CAClient,
		deviceManagerCli: builder.DevManagerCli,
		downstreamCert:   builder.DownstreamCertificate,
	}

	return svc
}

func (svc *DMSManagerServiceImpl) SetService(service DMSManagerService) {
	svc.service = service
}

type GetDMSStatsInput struct{}

func (svc DMSManagerServiceImpl) GetDMSStats(ctx context.Context, input GetDMSStatsInput) (*models.DMSStats, error) {
	total, err := svc.dmsStorage.Count(ctx)
	if err != nil {
		lDMS.Errorf("could not count dmss: %s", err)
		return &models.DMSStats{
			TotalDMSs: -1,
		}, nil
	}

	return &models.DMSStats{
		TotalDMSs: total,
	}, nil
}

type CreateDMSInput struct {
	ID       string `validate:"required"`
	Name     string `validate:"required"`
	Metadata map[string]any
	Settings models.DMSSettings `validate:"required"`
}

func (svc DMSManagerServiceImpl) CreateDMS(ctx context.Context, input CreateDMSInput) (*models.DMS, error) {
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
		ID:           input.ID,
		Name:         input.Name,
		Metadata:     input.Metadata,
		CreationDate: now,
		Settings:     input.Settings,
	}

	dms, err = svc.dmsStorage.Insert(context.Background(), dms)
	if err != nil {
		lDMS.Errorf("could not insert DMS '%s': %s", dms.ID, err)
		return nil, err
	}
	lDMS.Debugf("DMS '%s' persisted into storage engine", dms.ID)

	return dms, nil
}

type UpdateDMSInput struct {
	DMS models.DMS `validate:"required"`
}

func (svc DMSManagerServiceImpl) UpdateDMS(ctx context.Context, input UpdateDMSInput) (*models.DMS, error) {
	err := dmsValidate.Struct(input)
	if err != nil {
		lDMS.Errorf("struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}
	lDMS.Debugf("checking if DMS '%s' exists", input.DMS.ID)
	exists, dms, err := svc.dmsStorage.SelectExists(context.Background(), input.DMS.ID)
	if err != nil {
		lDMS.Errorf("something went wrong while checking if DMS '%s' exists in storage engine: %s", input.DMS.ID, err)
		return nil, err
	} else if !exists {
		lDMS.Errorf("DMS '%s' does not exist in storage engine", input.DMS.ID)
		return nil, errs.ErrDMSNotFound
	}

	dms.Metadata = input.DMS.Metadata
	dms.Name = input.DMS.Name
	dms.Settings = input.DMS.Settings

	lDMS.Debugf("updating DMS %s", input.DMS.ID)
	return svc.dmsStorage.Update(context.Background(), dms)
}

type GetDMSByIDInput struct {
	ID string `validate:"required"`
}

func (svc DMSManagerServiceImpl) GetDMSByID(ctx context.Context, input GetDMSByIDInput) (*models.DMS, error) {

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
	resources.ListInput[models.DMS]
}

func (svc DMSManagerServiceImpl) GetAll(ctx context.Context, input GetAllInput) (string, error) {
	bookmark, err := svc.dmsStorage.SelectAll(context.Background(), input.ExhaustiveRun, input.ApplyFunc, input.QueryParameters, nil)
	if err != nil {
		lDMS.Errorf("something went wrong while reading all DMSs from storage engine: %s", err)
		return "", err
	}

	return bookmark, nil
}

func (svc DMSManagerServiceImpl) CACerts(aps string) ([]*x509.Certificate, error) {
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

	caDistribSettings := dms.Settings.CADistributionSettings

	if caDistribSettings.IncludeLamassuSystemCA {
		if svc.downstreamCert == nil {
			lDMS.Warnf("downstream certificate is nil. skipping")
		} else {
			cas = append(cas, svc.downstreamCert)
		}
	}

	reqCAs := []string{}
	reqCAs = append(reqCAs, dms.Settings.CADistributionSettings.ManagedCAs...)

	if caDistribSettings.IncludeEnrollmentCA {
		reqCAs = append(reqCAs, dms.Settings.EnrollmentSettings.EnrollmentCA)
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

		lDMS.Debugf("got CA %s\n%s", caResponse.ID, helpers.CertificateToPEM((*x509.Certificate)(caResponse.Certificate.Certificate)))

		cas = append(cas, (*x509.Certificate)(caResponse.Certificate.Certificate))
	}

	return cas, nil
}

// Validation:
//   - Cert:
//     Only Bootstrap cert (CA issued By Lamassu)
func (svc DMSManagerServiceImpl) Enroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	lDMS.Debugf("checking if DMS '%s' exists", aps)
	dms, err := svc.service.GetDMSByID(ctx, GetDMSByIDInput{
		ID: aps,
	})
	if err != nil {
		lDMS.Errorf("aborting enrollment process for device '%s'. Could not get DMS '%s': %s", csr.Subject.CommonName, aps, err)
		return nil, errs.ErrDMSNotFound
	}

	if dms.Settings.EnrollmentSettings.EnrollmentProtocol != models.EST {
		lDMS.Errorf("aborting enrollment process for device '%s'. DMS '%s' doesn't support EST Protocol", csr.Subject.CommonName, aps)
		return nil, errs.ErrDMSOnlyEST
	}

	estAuthOptions := dms.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030
	if estAuthOptions.AuthMode == models.ESTAuthModeClientCertificate {
		clientCert, hasValue := ctx.Value(models.ESTAuthModeClientCertificate).(*x509.Certificate)
		if !hasValue {
			lDMS.Errorf("aborting enrollment process for device '%s'. DMS '%s' is configured with '%s'. No client certificate was presented", csr.Subject.CommonName, dms.ID, estAuthOptions.AuthMode)
			return nil, errs.ErrDMSAuthModeNotSupported
		}

		lDMS.Debugf("presented client certificate has CommonName '%s' and SerialNumber '%s' issued by CA with CommonName '%s'", clientCert.Subject.CommonName, helpers.SerialNumberToString(clientCert.SerialNumber), clientCert.Issuer.CommonName)

		//check if certificate is a certificate issued by bootstrap CA
		validCertificate := false
		var validationCA *models.CACertificate
		estEnrollOpts := dms.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030
		for _, caID := range estEnrollOpts.AuthOptionsMTLS.ValidationCAs {
			ca, err := svc.caClient.GetCAByID(context.Background(), GetCAByIDInput{CAID: caID})
			if err != nil {
				lDMS.Warnf("could not obtain lamassu CA '%s'. Skipping to next validation CA: %s", caID, err)
				continue
			}

			err = helpers.ValidateCertificate((*x509.Certificate)(ca.Certificate.Certificate), *clientCert, true)
			if err != nil {
				lDMS.Debugf("invalid validation using CA [%s] with CommonName '%s', SerialNumber '%s'", ca.ID, ca.Subject.CommonName, ca.SerialNumber)
			} else {
				lDMS.Debugf("OK validation using CA [%s] with CommonName '%s', SerialNumber '%s'", ca.ID, ca.Subject.CommonName, ca.SerialNumber)
				validCertificate = true
				validationCA = ca
				break
			}
		}

		clientSN := helpers.SerialNumberToString(clientCert.SerialNumber)

		if !validCertificate {
			lDMS.Errorf("invalid enrollment. used certificate not authorized for this DMS. certificate has SerialNumber %s issued by CA %s", clientSN, clientCert.Issuer.CommonName)
			return nil, errs.ErrDMSEnrollInvalidCert
		}

		//checks against Lamassu, external OCSP or CRL
		couldCheckRevocation, isRevoked, err := svc.checkCertificateRevocation(ctx, clientCert, (*x509.Certificate)(validationCA.Certificate.Certificate))
		if err != nil {
			lDMS.Errorf("error while checking certificate revocation status: %s", err)
			return nil, err
		}

		if couldCheckRevocation {
			if isRevoked {
				return nil, fmt.Errorf("certificate is revoked")
			}
			lDMS.Infof("certificate is not revoked")
		} else {
			lDMS.Infof("could not verify certificate expiration. Assuming certificate as not-revoked")
		}

	} else if estAuthOptions.AuthMode == models.ESTAuthModeNoAuth {
		lDMS.Warnf("DMS %s is configured with NoAuth. Allowing enrollment", dms.ID)
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
		if dms.Settings.EnrollmentSettings.EnableReplaceableEnrollment {
			lDMS.Debugf("DMS '%s' allows new enrollments. continuing enrollment process for device '%s'", dms.ID, csr.Subject.CommonName)
			//revoke active certificate
			defer func() {
				_, err = svc.caClient.UpdateCertificateStatus(ctx, UpdateCertificateStatusInput{
					SerialNumber:     device.IdentitySlot.Secrets[device.IdentitySlot.ActiveVersion],
					NewStatus:        models.StatusRevoked,
					RevocationReason: ocsp.Superseded,
				})
				lDMS.Errorf("could not revoke certificate %s: %s", device.IdentitySlot.Secrets[device.IdentitySlot.ActiveVersion], err)
			}()
		} else {
			lDMS.Debugf("DMS '%s' forbids new enrollments. aborting enrollment process for device '%s'. consider switching NewEnrollment option ON in the DMS", dms.ID, csr.Subject.CommonName)
			return nil, fmt.Errorf("forbiddenNewEnrollment")
		}
	}

	if dms.Settings.EnrollmentSettings.RegistrationMode == models.JITP {
		if device == nil {
			lDMS.Debugf("DMS '%s' is configured with JustInTime registration. will create device with ID %s", dms.ID, csr.Subject.CommonName)
			//contact device manager and register device first
			device, err = svc.deviceManagerCli.CreateDevice(CreateDeviceInput{
				ID:        csr.Subject.CommonName,
				Alias:     csr.Subject.CommonName,
				Tags:      dms.Settings.EnrollmentSettings.DeviceProvisionProfile.Tags,
				Metadata:  dms.Settings.EnrollmentSettings.DeviceProvisionProfile.Metadata,
				Icon:      dms.Settings.EnrollmentSettings.DeviceProvisionProfile.Icon,
				IconColor: dms.Settings.EnrollmentSettings.DeviceProvisionProfile.IconColor,
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
		CAID:         dms.Settings.EnrollmentSettings.EnrollmentCA,
		CertRequest:  (*models.X509CertificateRequest)(csr),
		Subject:      nil,
		SignVerbatim: true,
	})
	if err != nil {
		lDMS.Errorf("could issue certificate for device '%s': %s", csr.Subject.CommonName, err)
		return nil, err
	}

	bindMode := models.DeviceEventTypeProvisioned
	if device.IdentitySlot == nil {
		bindMode = models.DeviceEventTypeProvisioned
	} else {
		bindMode = models.DeviceEventTypeReProvisioned
	}

	_, err = svc.service.BindIdentityToDevice(ctx, BindIdentityToDeviceInput{
		DeviceID:                device.ID,
		CertificateSerialNumber: crt.SerialNumber,
		BindMode:                bindMode,
	})
	if err != nil {
		return nil, err
	}

	return (*x509.Certificate)(crt.Certificate), nil
}

func (svc DMSManagerServiceImpl) Reenroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	lDMS.Debugf("checking if DMS '%s' exists", aps)
	dms, err := svc.service.GetDMSByID(ctx, GetDMSByIDInput{
		ID: aps,
	})
	if err != nil {
		lDMS.Errorf("aborting reenrollment process for device '%s'. Could not get DMS '%s': %s", csr.Subject.CommonName, aps, err)
		return nil, errs.ErrDMSNotFound
	}

	if dms.Settings.EnrollmentSettings.EnrollmentProtocol != models.EST {
		lDMS.Errorf("aborting reenrollment process for device '%s'. DMS '%s' doesn't support EST Protocol", csr.Subject.CommonName, aps)
		return nil, errs.ErrDMSOnlyEST
	}

	enrollCAID := dms.Settings.EnrollmentSettings.EnrollmentCA
	enrollCA, err := svc.caClient.GetCAByID(context.Background(), GetCAByIDInput{
		CAID: enrollCAID,
	})
	if err != nil {
		lDMS.Errorf("could not get enroll CA with ID=%s: %s", enrollCAID, err)
		return nil, err
	}

	if dms.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthMode == models.ESTAuthModeClientCertificate {
		clientCert, hasValue := ctx.Value(models.ESTAuthModeClientCertificate).(*x509.Certificate)
		if !hasValue {
			lDMS.Errorf("aborting reenrollment process for device '%s'. No client certificate was presented", csr.Subject.CommonName)
			return nil, errs.ErrDMSAuthModeNotSupported
		}

		lDMS.Debugf("presented client certificate has CN=%s and SN=%s issued by CA with CommonName '%s'", clientCert.Subject.CommonName, helpers.SerialNumberToString(clientCert.SerialNumber), clientCert.Issuer.CommonName)

		validCertificate := false
		var validationCA *x509.Certificate
		//check if certificate is a certificate issued by Enroll CA
		lDMS.Debugf("validating client certificate using EST Enrollment CA witch has ID=%s CN=%s SN=%s", enrollCAID, enrollCA.Certificate.Subject.CommonName, enrollCA.SerialNumber)
		err = helpers.ValidateCertificate((*x509.Certificate)(enrollCA.Certificate.Certificate), *clientCert, false)
		if err != nil {
			lDMS.Warnf("invalid validation using enroll CA: %s", err)
		} else {
			lDMS.Debugf("OK validation using enroll")
			validationCA = (*x509.Certificate)(enrollCA.Certificate.Certificate)
			validCertificate = true
		}

		if !validCertificate {
			estReEnrollOpts := dms.Settings.ReEnrollmentSettings
			aValCAsCtr := len(estReEnrollOpts.AdditionalValidationCAs)
			lDMS.Debugf("could not validate client certificate using enroll CA. Will try validating using Additional Validation CAs")
			lDMS.Debugf("DMS has %d additional validation CAs", aValCAsCtr)
			//check if certificate is a certificate issued by Extra Val CAs

			for idx, caID := range estReEnrollOpts.AdditionalValidationCAs {
				lDMS.Debugf("[%d/%d] obtainig validation with ID %s", idx, aValCAsCtr, caID)
				ca, err := svc.caClient.GetCAByID(context.Background(), GetCAByIDInput{CAID: caID})
				if err != nil {
					lDMS.Warnf("[%d/%d] could not obtain lamassu CA with ID %s. Skipping to next validation CA: %s", idx, aValCAsCtr, caID, err)
					continue
				}

				err = helpers.ValidateCertificate((*x509.Certificate)(ca.Certificate.Certificate), *clientCert, false)
				if err != nil {
					lDMS.Debugf("[%d/%d] invalid validation using CA [%s] with CommonName '%s', SerialNumber '%s'", idx, aValCAsCtr, ca.ID, ca.Subject.CommonName, ca.SerialNumber)
				} else {
					lDMS.Debugf("[%d/%d] OK validation using CA [%s] with CommonName '%s', SerialNumber '%s'", idx, aValCAsCtr, ca.ID, ca.Subject.CommonName, ca.SerialNumber)
					validCertificate = true
					break
				}
			}
		}

		//Check if EXPIRED
		now := time.Now()
		if clientCert.NotBefore.After(now) {
			if dms.Settings.ReEnrollmentSettings.EnableExpiredRenewal {
				lDMS.Infof("presented an expired certificate by %s, but DMS allows expired renewals. Continuing", now.Sub(clientCert.NotBefore))
			} else {
				lDMS.Errorf("aborting reenrollment. Device has a valid but expired certificate")
				return nil, fmt.Errorf("expired certificate")
			}
		}

		//checks against Lamassu, external OCSP or CRL
		couldCheckRevocation, isRevoked, err := svc.checkCertificateRevocation(ctx, clientCert, (*x509.Certificate)(validationCA))
		if err != nil {
			lDMS.Errorf("error while checking certificate revocation status: %s", err)
			return nil, err
		}

		if couldCheckRevocation {
			lDMS.Warnf("certificate is revoked")
			if isRevoked {
				return nil, fmt.Errorf("certificate is revoked")
			}
			lDMS.Infof("certificate is not revoked")
		} else {
			lDMS.Infof("could not verify certificate expiration. Assuming certificate as not-revoked")
		}

	} else {
		lDMS.Warnf("allowing reenroll: using NO AUTH mode")
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

	currentDeviceCertSN := device.IdentitySlot.Secrets[device.IdentitySlot.ActiveVersion]
	currentDeviceCert, err := svc.caClient.GetCertificateBySerialNumber(ctx, GetCertificatesBySerialNumberInput{
		SerialNumber: currentDeviceCertSN,
	})
	if err != nil {
		lDMS.Errorf("could not get device certificate '%s' from CA service: %s", currentDeviceCertSN, err)
		return nil, fmt.Errorf("could not get device certificate")
	}

	lDMS.Debugf("device %s ActiveVersion=%d for IdentitySlot is certificate with SN=%s", device.ID, device.IdentitySlot.ActiveVersion, currentDeviceCert.SerialNumber)

	lDMS.Debugf("checking CSR has same RawSubject as the previous enrollment at byte level. DeviceID=%s ActiveVersion=%d", device.ID, device.IdentitySlot.ActiveVersion)
	//Compare CRT & CSR Subject bytes
	if slices.Compare(currentDeviceCert.Certificate.RawSubject, csr.RawSubject) != 0 {
		lDMS.Tracef("current device certificate raw subject (len=%d):\n%v", len(currentDeviceCert.Certificate.RawSubject), currentDeviceCert.Certificate.RawSubject)
		lDMS.Tracef("incoming csr raw subject (len=%d):\n%v", len(csr.RawSubject), csr.RawSubject)
		lDMS.Warnf("incoming CSR for device %s has different RawSubject compared with previous enrollment with ActiveVersion=%d. Will try shallow comparison", device.ID, device.IdentitySlot.ActiveVersion)

		type subjectComp struct {
			claim    string
			crtClaim string
			csrClaim string
		}

		crtSub := currentDeviceCert.Certificate.Subject
		csrSub := csr.Subject
		pairsToCompare := []subjectComp{
			{claim: "CommonName", crtClaim: crtSub.CommonName, csrClaim: csrSub.CommonName},
			{claim: "OrganizationalUnit", crtClaim: strings.Join(crtSub.OrganizationalUnit, ","), csrClaim: strings.Join(csrSub.OrganizationalUnit, ",")},
			{claim: "Organization", crtClaim: strings.Join(crtSub.Organization, ","), csrClaim: strings.Join(csrSub.Organization, ",")},
			{claim: "Locality", crtClaim: strings.Join(crtSub.Locality, ","), csrClaim: strings.Join(csrSub.Locality, ",")},
			{claim: "Province", crtClaim: strings.Join(crtSub.Province, ","), csrClaim: strings.Join(csrSub.Province, ",")},
			{claim: "Country", crtClaim: strings.Join(crtSub.Country, ","), csrClaim: strings.Join(csrSub.Country, ",")},
		}
		for _, pair2Comp := range pairsToCompare {
			if pair2Comp.crtClaim != pair2Comp.csrClaim {
				lDMS.Errorf("current device certificate and csr differ in claim %s. crt got '%s' while csr got '%s'", pair2Comp.claim, pair2Comp.crtClaim, pair2Comp.csrClaim)
				return nil, fmt.Errorf("invalid RawSubject bytes")
			}
		}

	}

	now := time.Now()
	lDMS.Debugf("checking if DMS allows enrollment at current delta for device %s", device.ID)

	comparisonTimeThreshold := currentDeviceCert.Certificate.NotAfter.Add(-time.Duration(dms.Settings.ReEnrollmentSettings.ReEnrollmentDelta))
	lDMS.Debugf(
		"current device certificate expires at %s (%s duration). DMS allows reenrolling %s. Reenroll window opens %s. (delta=%s)",
		currentDeviceCert.Certificate.NotAfter.UTC().Format("2006-01-02T15:04:05Z07:00"),
		models.TimeDuration(currentDeviceCert.Certificate.NotAfter.Sub(now)).String(),
		dms.Settings.ReEnrollmentSettings.ReEnrollmentDelta.String(),
		comparisonTimeThreshold.UTC().Format("2006-01-02T15:04:05Z07:00"),
		models.TimeDuration(now.Sub(comparisonTimeThreshold)).String(),
	)

	//Check if current cert is REVOKED
	if currentDeviceCert.Status == models.StatusRevoked {
		lDMS.Warnf("aborting reenrollment as certificate %s is revoked with status code %s", currentDeviceCertSN, currentDeviceCert.RevocationReason)
		return nil, fmt.Errorf("revoked certificate")
	}

	//Check if Not in DMS ReEnroll Window
	if comparisonTimeThreshold.After(now) {
		lDMS.Errorf("aborting reenrollment. Device has a valid certificate but DMS reenrollment window does not allow reenrolling with %s delta. Update DMS or wait until the reenrollment window is open", models.TimeDuration(now.Sub(comparisonTimeThreshold)).String())
		return nil, fmt.Errorf("invalid reenroll window")
	}

	crt, err := svc.caClient.SignCertificate(context.Background(), SignCertificateInput{
		CAID:         dms.Settings.EnrollmentSettings.EnrollmentCA,
		CertRequest:  (*models.X509CertificateRequest)(csr),
		Subject:      nil,
		SignVerbatim: true,
	})
	if err != nil {
		lDMS.Errorf("could not issue certificate for device '%s': %s", csr.Subject.CommonName, err)
		return nil, err
	}

	//detach certificate from meta
	delete(currentDeviceCert.Metadata, models.CAAttachedToDeviceKey)
	delete(currentDeviceCert.Metadata, models.CAMetadataMonitoringExpirationDeltasKey)
	_, err = svc.caClient.UpdateCertificateMetadata(ctx, UpdateCertificateMetadataInput{
		SerialNumber: currentDeviceCertSN,
		Metadata:     currentDeviceCert.Metadata,
	})
	if err != nil {
		lDMS.Errorf("could not update superseded certificate metadata %s: %s", currentDeviceCert.SerialNumber, err)
		return nil, err
	}

	//revoke superseded cert if active. Don't try revoking expired or already revoked since is not a valid transition for the CA service.
	if currentDeviceCert.Status == models.StatusActive {
		_, err = svc.caClient.UpdateCertificateStatus(ctx, UpdateCertificateStatusInput{
			SerialNumber:     currentDeviceCertSN,
			NewStatus:        models.StatusRevoked,
			RevocationReason: ocsp.Superseded,
		})
		if err != nil {
			lDMS.Errorf("could not update superseded certificate status to revoked %s: %s", currentDeviceCert.SerialNumber, err)
			return nil, err
		}
	}

	_, err = svc.service.BindIdentityToDevice(ctx, BindIdentityToDeviceInput{
		DeviceID:                device.ID,
		CertificateSerialNumber: crt.SerialNumber,
		BindMode:                models.DeviceEventTypeRenewed,
	})
	if err != nil {
		return nil, err
	}

	return (*x509.Certificate)(crt.Certificate), nil
}

func (svc DMSManagerServiceImpl) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, interface{}, error) {
	var privKey any
	var err error

	keyType, hasValue := ctx.Value(models.ESTServerKeyGenKeyType).(x509.PublicKeyAlgorithm)
	if !hasValue {
		lDMS.Debugf("no valid key type found. Defaulting to RSA")
		keyType = x509.RSA
	}

	keySize, hasKeySizeValue := ctx.Value(models.ESTServerKeyGenBitSize).(int)

	switch keyType {
	case x509.RSA:
		if hasKeySizeValue {
			if keySize%1024 != 0 {
				lDMS.Warnf("invalid key size of %d for RSA. Defaulting to 4096", keySize)
				keySize = 4096
			}
		} else {
			lDMS.Debugf("no key size specified. Defaulting to RSA 4096")
			keySize = 4096
		}

		privKey, err = rsa.GenerateKey(rand.Reader, keySize)
	case x509.ECDSA:
		var curve elliptic.Curve
		if hasKeySizeValue {
			switch keySize {
			case 224:
				curve = elliptic.P224()
			case 256:
				curve = elliptic.P256()
			case 384:
				curve = elliptic.P384()
			case 521:
				curve = elliptic.P521()
			default:
				lDMS.Warnf("invalid key size of %d for ECDSA. Defaulting to 256 curve", keySize)
				curve = elliptic.P256()
			}
		} else {
			lDMS.Debugf("no key size specified. Defaulting to ECDSA 256 curve")
			curve = elliptic.P256()
		}

		privKey, err = ecdsa.GenerateKey(curve, rand.Reader)
	default:
		return nil, nil, fmt.Errorf("unsupported key type %s", keyType)
	}

	fmt.Println(privKey, err)
	return nil, nil, fmt.Errorf("TODO")
}

// returns if the given certificate COULD BE checked for revocation (true means that it could be checked), and if it is revoked (true) or not (false)
func (svc DMSManagerServiceImpl) checkCertificateRevocation(ctx context.Context, cert *x509.Certificate, validationCA *x509.Certificate) (bool, bool, error) {
	revocationChecked := false
	revoked := true
	clientSN := helpers.SerialNumberToString(cert.SerialNumber)
	//check if revoked
	//  If cert is in Lamassu: check status
	//  If cert NOT in Lamassu (i.e. Issued Offline/Outside Lamassu), check if the certificate has CRL/OCSP in presented CRT.
	lmsCrt, err := svc.caClient.GetCertificateBySerialNumber(ctx, GetCertificatesBySerialNumberInput{
		SerialNumber: clientSN,
	})
	if err != nil {
		if err != errs.ErrCertificateNotFound {
			lDMS.Errorf("got unexpected error while searching certificate %s in Lamassu: %s", clientSN, err)
			return false, true, err
		}

		//Not Stored In lamassu. Check if CRL/OCSP
		if len(cert.OCSPServer) > 0 {
			//OCSP first
			for _, ocspInstance := range cert.OCSPServer {
				ocspResp, err := external_clients.GetOCSPResponse(ocspInstance, cert, validationCA, nil, true)
				if err != nil {
					lDMS.Warnf("could not get or validate ocsp response from server %s specified in the presented client certificate: %s", err, clientSN)
					lDMS.Warnf("checking with next ocsp server")
					continue
				}

				lDMS.Infof("successfully validated OCSP response with external %s OCSP server. Checking OCSP response status for %s certificate", ocspInstance, clientSN)
				if ocspResp.Status == ocsp.Revoked {
					lDMS.Warnf("certificate was revoked at %s with %s revocation reason", ocspResp.RevokedAt.String(), models.RevocationReasonMap[ocspResp.RevocationReason])
					return true, true, nil
				} else {
					lDMS.Infof("certificate is not revoked")
					return true, false, nil
				}
			}
		}

		if !revocationChecked && len(cert.CRLDistributionPoints) > 0 {
			//Try CRL
			for _, crlDP := range cert.CRLDistributionPoints {
				crl, err := external_clients.GetCRLResponse(crlDP, validationCA, nil, true)
				if err != nil {
					lDMS.Warnf("could not get or validate crl response from server %s specified in the presented client certificate: %s", err, clientSN)
					lDMS.Warnf("checking with next crl server")
					continue
				}

				idxClientCrt := slices.IndexFunc(crl.RevokedCertificateEntries, func(entry x509.RevocationListEntry) bool {
					return entry.SerialNumber == cert.SerialNumber
				})

				if idxClientCrt >= 0 {
					entry := crl.RevokedCertificateEntries[idxClientCrt]
					lDMS.Warnf("certificate was revoked at %s with %s revocation reason", entry.RevocationTime.String(), models.RevocationReasonMap[entry.ReasonCode])
					return true, true, nil
				} else {
					lDMS.Infof("certificate not revoked. Client certificate not in CRL: %s", clientSN)
					revocationChecked = true
					revoked = false
					//don't return, check other CRLs
				}
			}
		}
	} else {
		if lmsCrt.Status == models.StatusRevoked {
			lDMS.Errorf("Client certificate %s is revoked", clientSN)
			return true, true, nil
		} else {
			return true, false, nil
		}
	}

	return revocationChecked, revoked, nil
}

type BindIdentityToDeviceInput struct {
	DeviceID                string
	CertificateSerialNumber string
	BindMode                models.DeviceEventType
}

func (svc DMSManagerServiceImpl) BindIdentityToDevice(ctx context.Context, input BindIdentityToDeviceInput) (*models.BindIdentityToDeviceOutput, error) {
	crt, err := svc.caClient.GetCertificateBySerialNumber(ctx, GetCertificatesBySerialNumberInput{
		SerialNumber: input.CertificateSerialNumber,
	})
	if err != nil {
		return nil, err
	}

	device, err := svc.deviceManagerCli.GetDeviceByID(GetDeviceByIDInput{
		ID: input.DeviceID,
	})
	if err != nil {
		return nil, err
	}

	dms, err := svc.GetDMSByID(ctx, GetDMSByIDInput{
		ID: device.DMSOwner,
	})
	if err != nil {
		return nil, err
	}

	newMeta := crt.Metadata
	newMeta[models.CAMetadataMonitoringExpirationDeltasKey] = models.CAMetadataMonitoringExpirationDeltas{
		{
			Delta:     dms.Settings.ReEnrollmentSettings.PreventiveReEnrollmentDelta,
			Name:      "Preventive",
			Triggered: false,
		},
		{
			Delta:     dms.Settings.ReEnrollmentSettings.CriticalReEnrollmentDelta,
			Name:      "Critical",
			Triggered: false,
		},
	}
	newMeta[models.CAAttachedToDeviceKey] = models.CAAttachedToDevice{
		AuthorizedBy: struct {
			RAID string "json:\"ra_id\""
		}{RAID: dms.ID},
		DeviceID: device.ID,
	}

	crt, err = svc.caClient.UpdateCertificateMetadata(ctx, UpdateCertificateMetadataInput{
		SerialNumber: crt.SerialNumber,
		Metadata:     newMeta,
	})
	if err != nil {
		lDMS.Errorf("could not update certificate metadata with monitoring deltas for certificate with sn '%s': %s", crt.SerialNumber, err)
		return nil, err
	}

	idSlot := device.IdentitySlot
	if idSlot == nil {
		idSlot = &models.Slot[string]{
			Status:        models.SlotActive,
			ActiveVersion: 0,
			SecretType:    models.X509SlotProfileType,
			Secrets: map[int]string{
				0: crt.SerialNumber,
			},
			Events: map[time.Time]models.DeviceEvent{
				time.Now(): {
					EvenType: models.DeviceEventTypeProvisioned,
				},
			},
		}
	} else {
		idSlot.ActiveVersion = idSlot.ActiveVersion + 1
		idSlot.Status = models.SlotActive
		idSlot.Secrets[idSlot.ActiveVersion] = crt.SerialNumber

		idSlot.Events[time.Now()] = models.DeviceEvent{
			EvenType:          input.BindMode,
			EventDescriptions: fmt.Sprintf("New Active Version set to %d", idSlot.ActiveVersion),
		}
	}
	_, err = svc.deviceManagerCli.UpdateDeviceIdentitySlot(UpdateDeviceIdentitySlotInput{
		ID:   crt.Subject.CommonName,
		Slot: *idSlot,
	})
	if err != nil {
		lDMS.Errorf("could not update device '%s' identity slot. Aborting enrollment process: %s", device.ID, err)
		return nil, err
	}

	return &models.BindIdentityToDeviceOutput{
		Certificate: crt,
		DMS:         dms,
		Device:      device,
	}, nil
}
