package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"

	log "github.com/sirupsen/logrus"

	lamassuCAClient "github.com/lamassuiot/lamassuiot/pkg/ca/client"
	lamassuCAApi "github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	lamassuDevManagerClient "github.com/lamassuiot/lamassuiot/pkg/device-manager/client"
	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/common/api"
	dmsErrors "github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/errors"
	dmsRepository "github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/repository"
	lamassuEstClient "github.com/lamassuiot/lamassuiot/pkg/est/client"
	estErrors "github.com/lamassuiot/lamassuiot/pkg/est/server/api/errors"
	estserver "github.com/lamassuiot/lamassuiot/pkg/est/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/utils"
	"golang.org/x/exp/slices"
)

type Service interface {
	estserver.ESTService

	Health(ctx context.Context) bool
	CreateDMS(ctx context.Context, input *api.CreateDMSInput) (*api.CreateDMSOutput, error)
	UpdateDMSStatus(ctx context.Context, input *api.UpdateDMSStatusInput) (*api.UpdateDMSStatusOutput, error)
	UpdateDMSAuthorizedCAs(ctx context.Context, input *api.UpdateDMSAuthorizedCAsInput) (*api.UpdateDMSAuthorizedCAsOutput, error)
	UpdateDMS(ctx context.Context, input *api.UpdateDMSInput) (*api.UpdateDMSOutput, error)
	GetDMSs(ctx context.Context, input *api.GetDMSsInput) (*api.GetDMSsOutput, error)
	GetDMSByName(ctx context.Context, input *api.GetDMSByNameInput) (*api.GetDMSByNameOutput, error)
}

type DMSManagerService struct {
	service                 Service
	dmsRepository           dmsRepository.DeviceManufacturingServiceRepository
	lamassuCAClient         lamassuCAClient.LamassuCAClient
	lamassuDevManagerClient lamassuDevManagerClient.LamassuDeviceManagerClient
	UpstreamCert            *x509.Certificate
	DownstreamCA            *x509.Certificate
	UpstreamKey             interface{}
	DevManagerAddr          string
}

func NewDMSManagerService(dmsRepo dmsRepository.DeviceManufacturingServiceRepository, caClient *lamassuCAClient.LamassuCAClient, devManagerClient *lamassuDevManagerClient.LamassuDeviceManagerClient, downstreamCA, upstreamCert *x509.Certificate, upstreamKey interface{}, devManagerAddr string) Service {
	svc := DMSManagerService{
		dmsRepository:           dmsRepo,
		lamassuCAClient:         *caClient,
		lamassuDevManagerClient: *devManagerClient,
		UpstreamCert:            upstreamCert,
		UpstreamKey:             upstreamKey,
		DownstreamCA:            downstreamCA,
		DevManagerAddr:          devManagerAddr,
	}

	svc.service = &svc

	return &svc
}

func (s *DMSManagerService) SetService(svc Service) {
	s.service = svc
}

func (s *DMSManagerService) Health(ctx context.Context) bool {
	return true
}

func (s *DMSManagerService) CreateDMS(ctx context.Context, input *api.CreateDMSInput) (*api.CreateDMSOutput, error) {
	var privateKey interface{}
	dms := api.DeviceManufacturingService{
		Name:     input.Name,
		Aws:      input.Aws,
		Status:   api.DMSStatusPendingApproval,
		CloudDMS: input.CloudDMS,
		RemoteAccessIdentity: &api.RemoteAccessIdentity{
			Subject:     api.Subject{},
			KeyMetadata: api.KeyStrengthMetadata{},
		},
	}

	if !input.CloudDMS {
		subject := pkix.Name{
			CommonName:         input.RemoteAccessIdentity.Subject.CommonName,
			Country:            []string{input.RemoteAccessIdentity.Subject.Country},
			Province:           []string{input.RemoteAccessIdentity.Subject.State},
			Locality:           []string{input.RemoteAccessIdentity.Subject.Locality},
			Organization:       []string{input.RemoteAccessIdentity.Subject.Organization},
			OrganizationalUnit: []string{input.RemoteAccessIdentity.Subject.OrganizationUnit},
		}

		if !input.RemoteAccessIdentity.ExternalKeyGeneration {
			if input.RemoteAccessIdentity.KeyMetadata.KeyType == api.RSA {
				rsaKey, _ := rsa.GenerateKey(rand.Reader, input.RemoteAccessIdentity.KeyMetadata.KeyBits)
				privateKey = rsaKey
			} else {
				var curve elliptic.Curve
				switch input.RemoteAccessIdentity.KeyMetadata.KeyBits {
				case 224:
					curve = elliptic.P224()
				case 256:
					curve = elliptic.P256()
				case 384:
					curve = elliptic.P384()
				case 521:
					curve = elliptic.P521()
				default:
					return &api.CreateDMSOutput{}, errors.New("unsuported key size for ECDSA key")
				}

				ecdsaKey, _ := ecdsa.GenerateKey(curve, rand.Reader)
				privateKey = ecdsaKey
			}

			template := x509.CertificateRequest{
				Subject:            subject,
				SignatureAlgorithm: x509.SHA256WithRSA,
			}

			csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
			csr, _ := x509.ParseCertificateRequest(csrBytes)

			dms.RemoteAccessIdentity.KeyMetadata = input.RemoteAccessIdentity.KeyMetadata
			dms.RemoteAccessIdentity.Subject = input.RemoteAccessIdentity.Subject
			dms.RemoteAccessIdentity.CertificateRequest = csr
			dms.RemoteAccessIdentity.AuthorizedCAs = []string{}
		} else {
			dms.RemoteAccessIdentity.CertificateRequest = input.RemoteAccessIdentity.CertificateRequest
		}
	} else {
		dms.IdentityProfile = input.IdentityProfile
		dms.IdentityProfile.EnrollmentSettings.AuthorizedCA = ""
	}

	err := s.dmsRepository.Insert(ctx, dms)
	if err != nil {
		return &api.CreateDMSOutput{}, err
	}

	dmsOut, err := s.dmsRepository.SelectByName(ctx, dms.Name)
	if err != nil {
		return &api.CreateDMSOutput{}, err
	}

	return &api.CreateDMSOutput{
		DMS:        dmsOut,
		PrivateKey: privateKey,
	}, nil
}

func (s *DMSManagerService) UpdateDMS(ctx context.Context, input *api.UpdateDMSInput) (*api.UpdateDMSOutput, error) {
	err := s.dmsRepository.UpdateDMS(ctx, input.DeviceManufacturingService)
	if err != nil {
		return nil, err
	}

	dmsOut, err := s.service.GetDMSByName(ctx, &api.GetDMSByNameInput{
		Name: input.Name,
	})
	if err != nil {
		return nil, err
	}

	return &api.UpdateDMSOutput{
		DeviceManufacturingService: dmsOut.DeviceManufacturingService,
	}, nil
}

func (s *DMSManagerService) UpdateDMSStatus(ctx context.Context, input *api.UpdateDMSStatusInput) (*api.UpdateDMSStatusOutput, error) {
	peningApprovalNextStatus := []api.DMSStatus{
		api.DMSStatusApproved,
		api.DMSStatusRejected,
	}
	rejectedNextStatus := []api.DMSStatus{}
	approvedNextStatus := []api.DMSStatus{
		api.DMSStatusExpired,
		api.DMSStatusRevoked,
	}
	expiredNextStatus := []api.DMSStatus{}
	revokedNextStatus := []api.DMSStatus{}

	dmsOutput, err := s.service.GetDMSByName(ctx, &api.GetDMSByNameInput{
		Name: input.Name,
	})
	if err != nil {
		return &api.UpdateDMSStatusOutput{}, err
	}

	dms := dmsOutput.DeviceManufacturingService

	var nextAllowedStatus []api.DMSStatus
	switch dms.Status {
	case api.DMSStatusPendingApproval:
		nextAllowedStatus = peningApprovalNextStatus
	case api.DMSStatusRejected:
		nextAllowedStatus = rejectedNextStatus
	case api.DMSStatusApproved:
		nextAllowedStatus = approvedNextStatus
	case api.DMSStatusExpired:
		nextAllowedStatus = expiredNextStatus
	case api.DMSStatusRevoked:
		nextAllowedStatus = revokedNextStatus
	default:
		return &api.UpdateDMSStatusOutput{}, errors.New("unsupported status")
	}

	if !slices.Contains(nextAllowedStatus, input.Status) {
		return &api.UpdateDMSStatusOutput{}, &dmsErrors.GenericError{
			StatusCode: http.StatusBadRequest,
			Message:    fmt.Sprintf("can not change from status %s to status %s", dms.Status, input.Status),
		}
	}

	switch input.Status {
	case api.DMSStatusApproved:
		dms.Status = api.DMSStatusApproved
		if !dms.CloudDMS {
			signOutput, err := s.lamassuCAClient.SignCertificateRequest(ctx, &lamassuCAApi.SignCertificateRequestInput{
				CAType:                    lamassuCAApi.CATypeDMSEnroller,
				CAName:                    "LAMASSU-DMS-MANAGER",
				CertificateSigningRequest: dms.RemoteAccessIdentity.CertificateRequest,
				SignVerbatim:              true,
			})
			if err != nil {
				return &api.UpdateDMSStatusOutput{}, err
			}

			dms.RemoteAccessIdentity.SerialNumber = utils.InsertNth(utils.ToHexInt(signOutput.Certificate.SerialNumber), 2)
			dms.RemoteAccessIdentity.Certificate = signOutput.Certificate

			err = s.dmsRepository.UpdateDMS(ctx, dms)
			if err != nil {
				return &api.UpdateDMSStatusOutput{}, err
			}
		}
		if err != nil {
			return &api.UpdateDMSStatusOutput{}, err
		}

	case api.DMSStatusRevoked:
		if !dms.CloudDMS {
			_, err = s.lamassuCAClient.RevokeCertificate(ctx, &lamassuCAApi.RevokeCertificateInput{
				CAType:                  lamassuCAApi.CATypeDMSEnroller,
				CAName:                  "LAMASSU-DMS-MANAGER",
				CertificateSerialNumber: dms.RemoteAccessIdentity.SerialNumber,
				RevocationReason:        "Manually revoked by DMS manager",
			})
			if err != nil {
				return &api.UpdateDMSStatusOutput{}, err
			}
		}

		dmsOutput.Status = api.DMSStatusRevoked
		err = s.dmsRepository.UpdateDMS(ctx, dmsOutput.DeviceManufacturingService)
		if err != nil {
			return &api.UpdateDMSStatusOutput{}, err
		}

	default:
		dmsOutput.Status = input.Status
		err = s.dmsRepository.UpdateDMS(ctx, dmsOutput.DeviceManufacturingService)
		if err != nil {
			return &api.UpdateDMSStatusOutput{}, err
		}
	}

	getDMSOutput, err := s.service.GetDMSByName(ctx, &api.GetDMSByNameInput{
		Name: input.Name,
	})
	if err != nil {
		return &api.UpdateDMSStatusOutput{}, err
	}

	return &api.UpdateDMSStatusOutput{
		DeviceManufacturingService: getDMSOutput.DeviceManufacturingService,
	}, nil
}

func (s *DMSManagerService) GetDMSs(ctx context.Context, input *api.GetDMSsInput) (*api.GetDMSsOutput, error) {
	totalDMS, dmsS, err := s.dmsRepository.SelectAll(ctx, input.QueryParameters)
	if err != nil {
		return &api.GetDMSsOutput{}, err
	}

	var dmsList []api.DeviceManufacturingService
	for _, v := range dmsS {
		dmsOutput, err := s.service.GetDMSByName(ctx, &api.GetDMSByNameInput{
			Name: v.Name,
		})
		if err != nil {
			continue
		}
		dmsList = append(dmsList, dmsOutput.DeviceManufacturingService)
	}

	return &api.GetDMSsOutput{
		TotalDMSs: totalDMS,
		DMSs:      dmsList,
	}, nil
}

func (s *DMSManagerService) UpdateDMSAuthorizedCAs(ctx context.Context, input *api.UpdateDMSAuthorizedCAsInput) (*api.UpdateDMSAuthorizedCAsOutput, error) {
	dmsOutput, err := s.service.GetDMSByName(ctx, &api.GetDMSByNameInput{
		Name: input.Name,
	})
	if err != nil {
		return &api.UpdateDMSAuthorizedCAsOutput{}, err
	}

	if dmsOutput.Status != api.DMSStatusApproved {
		return &api.UpdateDMSAuthorizedCAsOutput{}, &dmsErrors.GenericError{
			StatusCode: http.StatusBadRequest,
			Message:    "DMS is not approved, can not update authorized CAs",
		}
	}

	if dmsOutput.CloudDMS {
		if len(input.AuthorizedCAs) != 1 {
			return &api.UpdateDMSAuthorizedCAsOutput{}, &dmsErrors.GenericError{
				StatusCode: http.StatusBadRequest,
				Message:    "There is more than one authorized CA",
			}
		}

		dmsOutput.IdentityProfile.EnrollmentSettings.AuthorizedCA = input.AuthorizedCAs[0]
	} else {
		dmsOutput.RemoteAccessIdentity.AuthorizedCAs = input.AuthorizedCAs
	}

	err = s.dmsRepository.UpdateDMS(ctx, dmsOutput.DeviceManufacturingService)
	if err != nil {
		return &api.UpdateDMSAuthorizedCAsOutput{}, err
	}

	dmsOutput, err = s.service.GetDMSByName(ctx, &api.GetDMSByNameInput{
		Name: input.Name,
	})
	if err != nil {
		return &api.UpdateDMSAuthorizedCAsOutput{}, err
	}

	return &api.UpdateDMSAuthorizedCAsOutput{
		DeviceManufacturingService: dmsOutput.DeviceManufacturingService,
	}, nil
}

func (s *DMSManagerService) GetDMSByName(ctx context.Context, input *api.GetDMSByNameInput) (*api.GetDMSByNameOutput, error) {
	dms, err := s.dmsRepository.SelectByName(ctx, input.Name)
	if err != nil {
		return &api.GetDMSByNameOutput{}, err
	}

	if !dms.CloudDMS {
		if dms.Status != api.DMSStatusPendingApproval && dms.Status != api.DMSStatusRejected {
			caOutput, err := s.lamassuCAClient.GetCertificateBySerialNumber(ctx, &lamassuCAApi.GetCertificateBySerialNumberInput{
				CAType:                  lamassuCAApi.CATypeDMSEnroller,
				CAName:                  "LAMASSU-DMS-MANAGER",
				CertificateSerialNumber: dms.RemoteAccessIdentity.SerialNumber,
			})
			if err != nil {
				return &api.GetDMSByNameOutput{}, err
			}

			if caOutput.Status == lamassuCAApi.StatusExpired && dms.Status != api.DMSStatusExpired {
				output, err := s.service.UpdateDMSStatus(ctx, &api.UpdateDMSStatusInput{
					Name:   dms.Name,
					Status: api.DMSStatusExpired,
				})
				if err != nil {
					return &api.GetDMSByNameOutput{}, err
				}

				dms = output.DeviceManufacturingService
			} else if caOutput.Status == lamassuCAApi.StatusRevoked && dms.Status != api.DMSStatusRevoked {
				output, err := s.service.UpdateDMSStatus(ctx, &api.UpdateDMSStatusInput{
					Name:   dms.Name,
					Status: api.DMSStatusRevoked,
				})
				if err != nil {
					return &api.GetDMSByNameOutput{}, err
				}

				dms = output.DeviceManufacturingService
			}
		}

		if dms.RemoteAccessIdentity.Certificate != nil {
			keyType, keyBits, keyStrength := getPublicKeyInfoFromCRT(dms.RemoteAccessIdentity.Certificate)
			dms.RemoteAccessIdentity.KeyMetadata = api.KeyStrengthMetadata{
				KeyType:     keyType,
				KeyBits:     keyBits,
				KeyStrength: keyStrength,
			}
		} else {
			keyType, keyBits, keyStrength := getPublicKeyInfoFromCSR(dms.RemoteAccessIdentity.CertificateRequest)
			dms.RemoteAccessIdentity.KeyMetadata = api.KeyStrengthMetadata{
				KeyType:     keyType,
				KeyBits:     keyBits,
				KeyStrength: keyStrength,
			}
		}
	}

	return &api.GetDMSByNameOutput{
		DeviceManufacturingService: dms,
	}, nil
}

// -------------------------------------------------------------------------------------------------------------------
// 												EST Functions
// -------------------------------------------------------------------------------------------------------------------

func (s *DMSManagerService) CACerts(ctx context.Context, aps string) ([]*x509.Certificate, error) {
	dms, err := s.service.GetDMSByName(ctx, &api.GetDMSByNameInput{
		Name: aps,
	})
	if err != nil {
		return nil, err
	}

	if !dms.CloudDMS {
		return nil, &dmsErrors.GenericError{
			Message:    "dms not managed by lamassu",
			StatusCode: 403,
		}
	}

	cas := []*x509.Certificate{}

	if dms.IdentityProfile.CADistributionSettings.IncludeLamassuDownstreamCA {
		cas = append(cas, s.DownstreamCA)
	}

	if dms.IdentityProfile.CADistributionSettings.IncludeAuthorizedCA {
		cacert, err := s.lamassuCAClient.GetCAByName(ctx, &lamassuCAApi.GetCAByNameInput{
			CAType: lamassuCAApi.CATypePKI,
			CAName: dms.IdentityProfile.EnrollmentSettings.AuthorizedCA,
		})
		if err != nil {
			log.Warn(fmt.Sprintf("could not get authorized %s CA: ", dms.IdentityProfile.EnrollmentSettings.AuthorizedCA), err)
		} else {
			cas = append(cas, cacert.Certificate.Certificate)
		}
	}

	if dms.IdentityProfile.CADistributionSettings.IncludeBootstrapCAs {
		for _, bootstrapCA := range dms.IdentityProfile.EnrollmentSettings.BootstrapCAs {
			cacert, err := s.lamassuCAClient.GetCAByName(ctx, &lamassuCAApi.GetCAByNameInput{
				CAType: lamassuCAApi.CATypePKI,
				CAName: bootstrapCA,
			})
			if err != nil {
				log.Warn(fmt.Sprintf("could not get bootstrap %s CA: ", bootstrapCA), err)
			} else {
				cas = append(cas, cacert.Certificate.Certificate)
			}
		}
	}

	for _, ca := range dms.IdentityProfile.CADistributionSettings.ManagedCAs {
		cacert, err := s.lamassuCAClient.GetCAByName(ctx, &lamassuCAApi.GetCAByNameInput{
			CAType: lamassuCAApi.CATypePKI,
			CAName: ca,
		})
		if err != nil {
			log.Warn(fmt.Sprintf("could not get bootstrap %s CA: ", ca), err)
		} else {
			cas = append(cas, cacert.Certificate.Certificate)
		}
	}

	for _, ca := range dms.IdentityProfile.CADistributionSettings.StaticCAs {
		cas = append(cas, ca.Certificate)
	}

	return cas, nil
}

func (s *DMSManagerService) Enroll(ctx context.Context, csr *x509.CertificateRequest, clientCertificate *x509.Certificate, aps string) (*x509.Certificate, error) {
	dms, err := s.service.GetDMSByName(ctx, &api.GetDMSByNameInput{
		Name: aps,
	})
	if err != nil {
		return nil, err
	}

	if !dms.DeviceManufacturingService.CloudDMS {
		return nil, &estErrors.GenericError{
			Message:    "dms is not managed by lamasssu",
			StatusCode: 403,
		}
	}

	if dms.DeviceManufacturingService.Status != api.DMSStatusApproved {
		return nil, &estErrors.GenericError{
			Message:    "dms is not in the approved state",
			StatusCode: 403,
		}
	}

	verify := 0
	for _, ca := range dms.DeviceManufacturingService.IdentityProfile.EnrollmentSettings.BootstrapCAs {
		cacert, err := s.lamassuCAClient.GetCAByName(ctx, &lamassuCAApi.GetCAByNameInput{
			CAType: lamassuCAApi.CATypePKI,
			CAName: ca,
		})
		if err != nil {
			return nil, err
		}
		err = s.verifyCertificate(clientCertificate, cacert.CACertificate.Certificate.Certificate, false)
		if err == nil {
			break
		}
		verify = verify + 1
	}

	if verify == len(dms.DeviceManufacturingService.IdentityProfile.EnrollmentSettings.BootstrapCAs) {
		return nil, &estErrors.GenericError{
			Message:    "client certificate is not valid: " + err.Error(),
			StatusCode: 401,
		}
	}
	_, err = s.lamassuDevManagerClient.GetDeviceById(ctx, csr.Subject.CommonName)
	if err != nil {
		_, err = s.lamassuDevManagerClient.CreateDevice(ctx, csr.Subject.CommonName, csr.Subject.CommonName, aps, "-", dms.IdentityProfile.EnrollmentSettings.Tags, dms.IdentityProfile.EnrollmentSettings.Icon, dms.IdentityProfile.EnrollmentSettings.Color)
		if err != nil {
			log.Error(fmt.Sprintf("something went while registering the device: %s", err))
			return nil, err
		}
	}

	estURL, err := url.Parse(s.DevManagerAddr)
	if err != nil {
		log.Error(fmt.Sprintf("could not parse EST Server URL: %s", err))
		return nil, err
	}

	estClient, err := lamassuEstClient.NewESTClient(nil, estURL, s.UpstreamCert, s.UpstreamKey, nil, true)
	if err != nil {
		return nil, err
	}

	ctx = context.WithValue(ctx, "dmsName", dms.DeviceManufacturingService.Name)

	crt, err := estClient.Enroll(ctx, dms.DeviceManufacturingService.IdentityProfile.EnrollmentSettings.AuthorizedCA, csr)
	if err != nil {
		return nil, err
	}
	return crt, nil
}

func (s *DMSManagerService) Reenroll(ctx context.Context, csr *x509.CertificateRequest, cert *x509.Certificate, aps string) (*x509.Certificate, error) {
	device, err := s.lamassuDevManagerClient.GetDeviceById(ctx, csr.Subject.CommonName)
	if err != nil {
		return nil, err
	}

	if !reflect.DeepEqual(csr.Subject, cert.Subject) {
		return nil, &estErrors.GenericError{
			Message:    "CSR subject does not match certificate subject",
			StatusCode: 400,
		}
	}

	var dms *api.GetDMSByNameOutput
	if aps != "" {
		dms, err = s.GetDMSByName(ctx, &api.GetDMSByNameInput{
			Name: aps,
		})
		if err != nil {
			return nil, err
		}
		if device.Device.DmsName != dms.DeviceManufacturingService.Name {
			return nil, &estErrors.GenericError{
				StatusCode: http.StatusUnauthorized,
				Message:    "The DMS does not have the device provisioned.",
			}
		}
	} else {
		dms, err = s.GetDMSByName(ctx, &api.GetDMSByNameInput{
			Name: device.DmsName,
		})
		if err != nil {
			return nil, err
		}
	}

	if !dms.DeviceManufacturingService.CloudDMS {
		return nil, &estErrors.GenericError{
			StatusCode: http.StatusUnauthorized,
			Message:    "invalid dms mode: use cloud dms",
		}
	}
	caCert, err := s.lamassuCAClient.GetCAByName(ctx, &lamassuCAApi.GetCAByNameInput{
		CAType: lamassuCAApi.CATypePKI,
		CAName: dms.DeviceManufacturingService.IdentityProfile.EnrollmentSettings.AuthorizedCA,
	})
	if err != nil {
		return nil, err
	}

	err = s.verifyCertificate(cert, caCert.CACertificate.Certificate.Certificate, dms.DeviceManufacturingService.IdentityProfile.ReerollmentSettings.AllowExpiredRenewal)
	if err != nil {
		return nil, err
	}

	estURL, err := url.Parse(s.DevManagerAddr)
	if err != nil {
		log.Error(fmt.Sprintf("could not parse EST Server URL: %s", err))
		return nil, err
	}

	estClient, err := lamassuEstClient.NewESTClient(nil, estURL, s.UpstreamCert, s.UpstreamKey, nil, true)
	if err != nil {
		return nil, err
	}

	ctx = context.WithValue(ctx, "dmsName", dms.DeviceManufacturingService.Name)
	deviceNewCert, err := estClient.Reenroll(ctx, csr)

	if err != nil {
		return nil, err
	}

	return deviceNewCert, nil
}

func (s *DMSManagerService) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, cert *x509.Certificate, aps string) (*x509.Certificate, *rsa.PrivateKey, error) {
	return nil, nil, nil
}

// -------------------------------------------------------------------------------------------------------------------
// 													UTILS
// -------------------------------------------------------------------------------------------------------------------

func (s *DMSManagerService) verifyCertificate(clientCertificate *x509.Certificate, caCertificate *x509.Certificate, allowExpiredRenewal bool) error {
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(caCertificate)

	opts := x509.VerifyOptions{
		Roots:     clientCAs,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cert, _ := s.lamassuCAClient.GetCertificateBySerialNumber(context.Background(), &lamassuCAApi.GetCertificateBySerialNumberInput{
		CAType:                  lamassuCAApi.CATypePKI,
		CAName:                  caCertificate.Subject.CommonName,
		CertificateSerialNumber: utils.InsertNth(utils.ToHexInt(clientCertificate.SerialNumber), 2),
	})
	_, err := clientCertificate.Verify(opts)
	if err != nil {
		if cert.Status == lamassuCAApi.StatusExpired && !allowExpiredRenewal {
			return errors.New("could not verify client certificate: " + err.Error())
		}

	}

	if cert.Status == lamassuCAApi.StatusRevoked {
		return errors.New("certificate status is: " + string(cert.Status))
	}
	return nil
}

func getPublicKeyInfoFromCSR(csr *x509.CertificateRequest) (api.KeyType, int, api.KeyStrength) {
	var keyBits int
	var keyType api.KeyType

	keyType = api.ParseKeyType(csr.PublicKeyAlgorithm.String())
	switch keyType {
	case api.RSA:
		keyBits = csr.PublicKey.(*rsa.PublicKey).N.BitLen()
	case api.ECDSA:
		keyBits = csr.PublicKey.(*ecdsa.PublicKey).Params().BitSize
	}

	var keyStrength api.KeyStrength = api.KeyStrengthLow
	switch keyType {
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

	return keyType, keyBits, keyStrength
}

func getPublicKeyInfoFromCRT(crt *x509.Certificate) (api.KeyType, int, api.KeyStrength) {
	var keyBits int
	var keyType api.KeyType

	keyType = api.ParseKeyType(crt.PublicKeyAlgorithm.String())
	switch keyType {
	case api.RSA:
		keyBits = crt.PublicKey.(*rsa.PublicKey).N.BitLen()
	case api.ECDSA:
		keyBits = crt.PublicKey.(*ecdsa.PublicKey).Params().BitSize
	}

	var keyStrength api.KeyStrength = api.KeyStrengthLow
	switch keyType {
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

	return keyType, keyBits, keyStrength
}
