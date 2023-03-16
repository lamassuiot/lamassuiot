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

	"github.com/jakehl/goid"
	"github.com/lamassuiot/lamassuiot/pkg/errs"
	"github.com/lamassuiot/lamassuiot/pkg/helppers"
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
	Create(input CreateInput) (*models.DMS, string, error)
	UpdateStatus(input UpdateStatusInput) (*models.DMS, error)
	UpdateIdentityProfile(input UpdateIdentityProfileInput) (*models.DMS, error)
	GetDMSByID(input GetDMSByIDInput) (*models.DMS, error)
	GetAll(input GetAllInput) (string, error)
}

type dmsManagerServiceImpl struct {
	dmsCAID        string
	downstreamCert *x509.Certificate
	dmsStorage     storage.DMSRepo
	caClient       CAService
}

type ServiceDMSBuilder struct {
	DownstreamCert *x509.Certificate
	CAClient       CAService
	DMSStorage     storage.DMSRepo
}

func NewDMSManagerService(builder ServiceDMSBuilder) DMSManagerService {
	return &dmsManagerServiceImpl{
		dmsCAID:        "",
		dmsStorage:     builder.DMSStorage,
		caClient:       builder.CAClient,
		downstreamCert: builder.DownstreamCert,
	}
}

type CreateInput struct {
	CloudDMS                    bool
	Name                        string
	Metadata                    map[string]string
	Tags                        []string
	RemoteAccessIdentity        *RemoteAccessIdentity
	PreventiveReenrollmentDelta models.TimeDuration
	CriticalReenrollmentDetla   models.TimeDuration
}

type RemoteAccessIdentity struct {
	Csr     *models.X509CertificateRequest
	Subject *models.Subject
}

func (svc dmsManagerServiceImpl) Create(input CreateInput) (*models.DMS, string, error) {
	now := time.Now()
	generatedPrivKey := ""

	dms := &models.DMS{
		ID:           goid.NewV4UUID().String(),
		Status:       models.PendingACKDMSStatus,
		Name:         input.Name,
		CloudDMS:     input.CloudDMS,
		Metadata:     input.Metadata,
		Tags:         input.Tags,
		CreationDate: now,
		IdentityProfile: &models.IdentityProfile{
			EnrollmentSettings: models.EnrollmentSettings{
				AuthenticationMode: models.BootstrapCertificate,
				AuthorizedCAs:      []string{},
				DeviceProvisionSettings: models.DeviceProvisionSettings{
					Icon:       "Cg/CgSmartphoneChip",
					IconColor:  "#25ee32",
					Metadata:   map[string]string{},
					Tags:       []string{},
					ExtraSlots: map[string]models.SlotProfile{},
					IdentitySlot: models.IdentitySlot{
						PreventiveReenrollmentDelta: input.PreventiveReenrollmentDelta,
						CriticalReenrollmentDetla:   input.CriticalReenrollmentDetla,
					},
				},
				BootstrapCAs: []string{},
				BootstrapPSK: "",
			},
			CADistributionSettings: models.CADistributionSettings{
				IncludeLamassuSystemCA: true,
				IncludeBootstrapCAs:    false,
				IncludeAuthorizedCAs:   true,
				ManagedCAs:             []string{},
				StaticCAs:              []models.StaticCA{},
				DynamicCAs:             []models.DynamicCA{},
			},
		},
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
					Subject: helppers.SubjectToPkixName(*input.RemoteAccessIdentity.Subject),
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

	dms, err := svc.dmsStorage.Insert(context.Background(), &models.DMS{})
	if err != nil {
		return nil, "", err
	}

	return dms, generatedPrivKey, nil
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
					CAID:         svc.dmsCAID,
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

	if caDistribSettings.IncludeAuthorizedCAs {
		reqCAs = append(reqCAs, dms.IdentityProfile.EnrollmentSettings.AuthorizedCAs...)
	}

	if caDistribSettings.IncludeBootstrapCAs {
		reqCAs = append(reqCAs, dms.IdentityProfile.EnrollmentSettings.BootstrapCAs...)
	}

	for _, ca := range reqCAs {
		caResponse, err := svc.caClient.GetCAByID(GetCAByIDInput{
			ID: ca,
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

func (svc dmsManagerServiceImpl) Enroll(ctx context.Context, csr *x509.CertificateRequest, cert *x509.Certificate, aps string) (*x509.Certificate, error) {
	dms, err := svc.GetDMSByID(GetDMSByIDInput{
		ID: aps,
	})
	if err != nil {
		return nil, err
	}

	if !dms.CloudDMS {
		return nil, errs.SentinelAPIError{
			Status: http.StatusForbidden,
			Msg:    "invalid dms mode: use cloud dms",
		}
	}

	if dms.IdentityProfile.EnrollmentSettings.AuthenticationMode == models.BootstrapCertificate {
		certificate, err := svc.caClient.GetCertificateBySerialNumber(GetCertificatesBySerialNumberInput{
			SerialNumber: helppers.SerialNumberToString(cert.SerialNumber),
		})
		if err != nil {
			return nil, err
		}

		//validate fingerprint
		if certificate.Fingerprint != helppers.X509CertFingerprint(*cert) {
			log.Warnf("a modified certificate was presented while enrolling. tried to impersonate cert sn %s", certificate.SerialNumber)
			return nil, errs.SentinelAPIError{
				Status: http.StatusUnauthorized,
				Msg:    "invalid certificate",
			}
		}

		//check if certificate is a certificate issued by bootstrap CA
		if !slices.Contains(dms.IdentityProfile.EnrollmentSettings.BootstrapCAs, certificate.IssuerCAMetadata.ID) {
			log.Warnf("using a certificate not authorized for this DMS. used certificate with sn %s issued by CA %s", certificate.SerialNumber, certificate.IssuerCAMetadata.ID)
			return nil, errs.SentinelAPIError{
				Status: http.StatusForbidden,
				Msg:    "invalid certificate",
			}
		}

	} else if dms.IdentityProfile.EnrollmentSettings.AuthenticationMode == models.BootstrapPSK {

	}

	//contact device manager and register device first
	//contact device manager and enroll

	return nil, fmt.Errorf("TODO")
}

func (svc dmsManagerServiceImpl) Reenroll(ctx context.Context, csr *x509.CertificateRequest, cert *x509.Certificate, aps string) (*x509.Certificate, error) {
	return nil, fmt.Errorf("TODO")
}

func (svc dmsManagerServiceImpl) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, cert *x509.Certificate, aps string) (*x509.Certificate, interface{}, error) {
	return nil, nil, fmt.Errorf("TODO")
}
