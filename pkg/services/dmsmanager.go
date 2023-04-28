package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/errs"
	"github.com/lamassuiot/lamassuiot/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/models"
	"github.com/lamassuiot/lamassuiot/pkg/storage"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
)

var (
	ErrDMSStatusTransitionNotAllowed error = errors.New("DMS status transition not allowed")
	ErrDMSSMustBeActive              error = errors.New("DMS must be active")
)

type DMSManagerService interface {
	ESTService
	CreateDMS(input CreateDMSInput) (*models.DMS, string, error)
	UpdateStatus(input UpdateStatusInput) (*models.DMS, error)
	UpdateIdentityProfile(input UpdateIdentityProfileInput) (*models.DMS, error)
	GetDMSByID(input GetDMSByIDInput) (*models.DMS, error)
	GetAll(input GetAllInput) (string, error)
}

type dmsManagerServiceImpl struct {
	downstreamCert      *x509.Certificate
	deviceManagerESTCli ESTService
	deviceManagerCli    DeviceManagerService
	dmsStorage          storage.DMSRepo
	caClient            CAService
}

type ServiceDMSBuilder struct {
	DownstreamCert   *x509.Certificate
	DevManagerESTCli ESTService
	DevManagerCli    DeviceManagerService

	CAClient   CAService
	DMSStorage storage.DMSRepo
}

func NewDMSManagerService(builder ServiceDMSBuilder) DMSManagerService {
	return &dmsManagerServiceImpl{
		dmsStorage:          builder.DMSStorage,
		caClient:            builder.CAClient,
		downstreamCert:      builder.DownstreamCert,
		deviceManagerESTCli: builder.DevManagerESTCli,
		deviceManagerCli:    builder.DevManagerCli,
	}
}

type CreateDMSInput struct {
	Name                 string
	CloudDMS             bool
	Metadata             map[string]string
	Tags                 []string
	IdentityProfile      models.IdentityProfile
	RemoteAccessIdentity *RemoteAccessIdentityInput
}

type RemoteAccessIdentityInput struct {
	Csr     *models.X509CertificateRequest
	Subject *models.Subject
}

func (svc dmsManagerServiceImpl) CreateDMS(input CreateDMSInput) (*models.DMS, string, error) {
	if exists, err := svc.dmsStorage.Exists(context.Background(), input.Name); err != nil {
		return nil, "", err
	} else if exists {
		return nil, "", errs.SentinelAPIError{
			Status: http.StatusConflict,
			Msg:    "dms already exists",
		}
	}

	now := time.Now()
	generatedPrivKey := ""

	dms := &models.DMS{
		ID:              input.Name,
		Status:          models.PendingACKDMSStatus,
		Name:            input.Name,
		CloudDMS:        input.CloudDMS,
		Metadata:        input.Metadata,
		Tags:            input.Tags,
		CreationDate:    now,
		IdentityProfile: mergeAndBuildDefaulIDProfile(&input.IdentityProfile),
	}

	if !input.CloudDMS {
		if input.RemoteAccessIdentity != nil {
			var csr *x509.CertificateRequest
			if input.RemoteAccessIdentity.Csr != nil {
				csr = (*x509.CertificateRequest)(input.RemoteAccessIdentity.Csr)
			} else {
				key, err := rsa.GenerateKey(rand.Reader, 4096)
				if err != nil {
					return nil, "", err
				}

				pemEncodedKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
				generatedPrivKey = base64.StdEncoding.EncodeToString(pemEncodedKey)

				csrTmpl := &x509.CertificateRequest{
					Subject: helpers.SubjectToPkixName(*input.RemoteAccessIdentity.Subject),
				}

				csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, key)
				if err != nil {
					return nil, "", err
				}

				csr, err = x509.ParseCertificateRequest(csrBytes)
				if err != nil {
					return nil, "", err
				}
			}

			dms.RemoteAccessIdentity = &models.RemoteAccessIdentity{
				ExternalKeyGeneration: generatedPrivKey == "",
				CertificateRequest:    (*models.X509CertificateRequest)(csr),
				Certificate:           nil,
			}
		}
	}

	dms, err := svc.dmsStorage.Insert(context.Background(), dms)
	if err != nil {
		return nil, "", err
	}

	return dms, generatedPrivKey, nil
}

func mergeAndBuildDefaulIDProfile(idProfile *models.IdentityProfile) *models.IdentityProfile {
	if idProfile.EnrollmentSettings.DeviceProvisionSettings.Icon == "" {
		idProfile.EnrollmentSettings.DeviceProvisionSettings.Icon = "Cg/CgSmartphoneChip"
	}

	if idProfile.EnrollmentSettings.DeviceProvisionSettings.IconColor == "" {
		idProfile.EnrollmentSettings.DeviceProvisionSettings.IconColor = "#00FAFC"
	}

	return idProfile
}

type UpdateStatusInput struct {
	DMSID     string
	NewStatus models.DMSStatus
}

func (svc dmsManagerServiceImpl) UpdateStatus(input UpdateStatusInput) (*models.DMS, error) {
	dms, err := svc.dmsStorage.Select(context.Background(), input.DMSID)
	if err != nil {
		return nil, err
	}

	currentStatus := dms.Status
	if input.NewStatus != currentStatus {

		if currentStatus == models.PendingACKDMSStatus && input.NewStatus == models.ActiveDMSStatus {
			//allow
			if !dms.CloudDMS {
				csr := dms.RemoteAccessIdentity.CertificateRequest
				crt, err := svc.caClient.SignCertificate(SignCertificateInput{
					CAID:         string(models.CALocalRA),
					CertRequest:  csr,
					Subject:      models.Subject{},
					SignVerbatim: true,
				})

				if err != nil {
					return nil, err
				}

				dms.RemoteAccessIdentity.Certificate = crt
			}
		} else if currentStatus == models.ActiveDMSStatus && (input.NewStatus == models.ActiveDMSStatus || input.NewStatus == models.ExpiredDMSStatus) {
			//allow
		} else {
			//deny
			return nil, ErrDMSStatusTransitionNotAllowed
		}
	}

	dms.Status = input.NewStatus

	return svc.dmsStorage.Update(context.Background(), dms)
}

type UpdateIdentityProfileInput struct {
	DMSID              string
	NewIdentityProfile models.IdentityProfile
}

func (svc dmsManagerServiceImpl) UpdateIdentityProfile(input UpdateIdentityProfileInput) (*models.DMS, error) {
	dms, err := svc.dmsStorage.Select(context.Background(), input.DMSID)
	if err != nil {
		return nil, err
	}

	if dms.Status != models.ActiveDMSStatus {
		return nil, ErrDMSSMustBeActive
	}

	dms.IdentityProfile = &input.NewIdentityProfile

	return svc.dmsStorage.Update(context.Background(), dms)
}

type GetDMSByIDInput struct {
	ID string
}

func (svc dmsManagerServiceImpl) GetDMSByID(input GetDMSByIDInput) (*models.DMS, error) {
	return svc.dmsStorage.Select(context.Background(), input.ID)
}

type GetAllInput struct {
	ListInput[models.DMS]
}

func (svc dmsManagerServiceImpl) GetAll(input GetAllInput) (string, error) {
	bookmark, err := svc.dmsStorage.SelectAll(context.Background(), input.ExhaustiveRun, input.ApplyFunc, input.QueryParameters, nil)
	if err != nil {
		return "", err
	}

	return bookmark, nil
}

func (svc dmsManagerServiceImpl) CACerts(ctx context.Context, aps string) ([]*x509.Certificate, error) {
	cas := []*x509.Certificate{}

	dms, err := svc.dmsStorage.Select(context.Background(), aps)
	if err != nil {
		return nil, err
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

	for _, ca := range caDistribSettings.StaticCAs {
		cas = append(cas, (*x509.Certificate)(ca.Certificate))
	}

	for _, ca := range caDistribSettings.DynamicCAs {
		//TODO
		log.Warnf("TODO: missing dynamic ca func for ca %s", ca.Name)
	}

	return cas, fmt.Errorf("TODO")
}

// Validation:
//   - Cert:
//     Only Bootstrap cert (CA issued By Lamassu)
func (svc dmsManagerServiceImpl) Enroll(ctx context.Context, authMode models.ESTAuthMode, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	dms, err := svc.GetDMSByID(GetDMSByIDInput{
		ID: aps,
	})
	if err != nil {
		return nil, err
	}

	if !dms.CloudDMS {
		return nil, errs.SentinelAPIError{
			Status: http.StatusUnauthorized,
			Msg:    "invalid dms mode: use cloud dms",
		}
	}

	if dms.IdentityProfile.EnrollmentSettings.EnrollmentProtocol != models.EST {
		return nil, fmt.Errorf("only EST enrollment supported ")
	}

	estAuthOptions := dms.IdentityProfile.EnrollmentSettings.EnrollmentOptionsESTRFC7030
	if estAuthOptions.AuthMode != authMode {
		log.Errorf("invalid dms authentication used during enrollment for %s. Auth mode used %s. Auth mode configured for this DMS %s", csr.Subject.CommonName, authMode, estAuthOptions.AuthMode)
		return nil, errs.SentinelAPIError{
			Status: http.StatusUnauthorized,
			Msg:    "invalid auth mode for this DMS",
		}
	}

	if estAuthOptions.AuthMode != authMode {
		return nil, errs.SentinelAPIError{
			Status: http.StatusUnauthorized,
			Msg:    "authentication method used does not match the configured",
		}
	}

	if authMode != models.MutualTLS {
		return nil, errs.SentinelAPIError{
			Status: http.StatusUnauthorized,
			Msg:    fmt.Sprintf("authentication method '%s' not supported", authMode),
		}
	}

	certCtxVal := ctx.Value(authMode)
	cert, ok := certCtxVal.(*x509.Certificate)
	if !ok {
		return nil, errs.SentinelAPIError{
			Status: http.StatusInternalServerError,
			Msg:    "corrupt ctx. no certificate found",
		}
	}

	certificate, err := svc.caClient.GetCertificateBySerialNumber(GetCertificatesBySerialNumberInput{
		SerialNumber: helpers.SerialNumberToString(cert.SerialNumber),
	})
	if err != nil {
		return nil, err
	}

	//validate fingerprint
	if certificate.Fingerprint != helpers.X509CertFingerprint(*cert) {
		log.Warnf("a modified certificate was presented while enrolling. tried to impersonate cert sn %s", certificate.SerialNumber)
		return nil, errs.SentinelAPIError{
			Status: http.StatusUnauthorized,
			Msg:    "invalid certificate",
		}
	}

	//check if certificate is a certificate issued by bootstrap CA
	estEnrollOpts := dms.IdentityProfile.EnrollmentSettings.EnrollmentOptionsESTRFC7030
	if !slices.Contains(estEnrollOpts.AuthOptionsMTLS.ValidationCAs, certificate.IssuerCAMetadata.CAID) {
		log.Warnf("using a certificate not authorized for this DMS. used certificate with sn %s issued by CA %s", certificate.SerialNumber, certificate.IssuerCAMetadata.CAID)
		return nil, errs.SentinelAPIError{
			Status: http.StatusForbidden,
			Msg:    "invalid certificate",
		}
	}

	connectionMeta := map[string]string{}
	if headers, ok := ctx.Value(models.ESTHeaders).(http.Header); ok {
		if ua := headers.Get("user-agent"); ua != "" {
			connectionMeta["user-agent"] = ua
		}
	}
	//contact device manager and register device first
	_, err = svc.deviceManagerCli.CreateDevice(CreateDeviceInput{
		ID:                 csr.Subject.CommonName,
		Alias:              csr.Subject.CommonName,
		Tags:               dms.IdentityProfile.EnrollmentSettings.DeviceProvisionSettings.Tags,
		Metadata:           dms.IdentityProfile.EnrollmentSettings.DeviceProvisionSettings.Metadata,
		Icon:               dms.IdentityProfile.EnrollmentSettings.DeviceProvisionSettings.Icon,
		IconColor:          dms.IdentityProfile.EnrollmentSettings.DeviceProvisionSettings.IconColor,
		ConnectionMetadata: connectionMeta,
		DMSID:              dms.ID,
	})
	if err != nil {
		return nil, err
	}

	//contact device manager and enroll
	additionalHeaders := map[string][]string{
		"x-dms-id": {dms.ID},
	}

	ctx = context.WithValue(ctx, models.ESTHeaders, http.Header(additionalHeaders))
	return svc.deviceManagerESTCli.Enroll(ctx, models.MutualTLS, csr, dms.IdentityProfile.EnrollmentSettings.AuthorizedCA)
}

func (svc dmsManagerServiceImpl) Reenroll(ctx context.Context, authMode models.ESTAuthMode, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	return nil, fmt.Errorf("TODO")
}

func (svc dmsManagerServiceImpl) ServerKeyGen(ctx context.Context, authMode models.ESTAuthMode, csr *x509.CertificateRequest, aps string) (*x509.Certificate, interface{}, error) {
	return nil, nil, fmt.Errorf("TODO")
}
