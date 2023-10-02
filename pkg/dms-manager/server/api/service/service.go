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
	"time"

	log "github.com/sirupsen/logrus"

	lamassuDevManagerClient "github.com/lamassuiot/lamassuiot/pkg/device-manager/client"
	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/common/api"
	dmsErrors "github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/errors"
	dmsRepository "github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/repository"
	lamassuEstClient "github.com/lamassuiot/lamassuiot/pkg/est/client"
	estErrors "github.com/lamassuiot/lamassuiot/pkg/est/server/api/errors"
	estserver "github.com/lamassuiot/lamassuiot/pkg/est/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/utils"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	serviceV3 "github.com/lamassuiot/lamassuiot/pkg/v3/services"
	"golang.org/x/crypto/ocsp"
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
	lamassuCAClient         serviceV3.CAService
	lamassuDevManagerClient lamassuDevManagerClient.LamassuDeviceManagerClient
	UpstreamCert            *x509.Certificate
	DownstreamCA            *x509.Certificate
	UpstreamKey             interface{}
	DevManagerAddr          string
}

func NewDMSManagerService(dmsRepo dmsRepository.DeviceManufacturingServiceRepository, caClient serviceV3.CAService, devManagerClient *lamassuDevManagerClient.LamassuDeviceManagerClient, downstreamCA, upstreamCert *x509.Certificate, upstreamKey interface{}, devManagerAddr string) Service {
	svc := DMSManagerService{
		dmsRepository:           dmsRepo,
		lamassuCAClient:         caClient,
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
			signOutput, err := s.lamassuCAClient.SignCertificate(ctx, serviceV3.SignCertificateInput{
				CAID:        string(models.CALocalRA),
				CertRequest: (*models.X509CertificateRequest)(dms.RemoteAccessIdentity.CertificateRequest),
				Subject:     nil,
			})
			if err != nil {
				return &api.UpdateDMSStatusOutput{}, err
			}

			dms.RemoteAccessIdentity.SerialNumber = utils.InsertNth(utils.ToHexInt(signOutput.Certificate.SerialNumber), 2)
			dms.RemoteAccessIdentity.Certificate = (*x509.Certificate)(signOutput.Certificate)

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
			_, err = s.lamassuCAClient.UpdateCertificateStatus(ctx, serviceV3.UpdateCertificateStatusInput{
				SerialNumber:     dms.RemoteAccessIdentity.SerialNumber,
				NewStatus:        models.StatusRevoked,
				RevocationReason: ocsp.CessationOfOperation,
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
			caOutput, err := s.lamassuCAClient.GetCertificateBySerialNumber(ctx, serviceV3.GetCertificatesBySerialNumberInput{
				SerialNumber: dms.RemoteAccessIdentity.SerialNumber,
			})
			if err != nil {
				return &api.GetDMSByNameOutput{}, err
			}

			if caOutput.Status == models.StatusExpired && dms.Status != api.DMSStatusExpired {
				output, err := s.service.UpdateDMSStatus(ctx, &api.UpdateDMSStatusInput{
					Name:   dms.Name,
					Status: api.DMSStatusExpired,
				})
				if err != nil {
					return &api.GetDMSByNameOutput{}, err
				}

				dms = output.DeviceManufacturingService
			} else if caOutput.Status == models.StatusRevoked && dms.Status != api.DMSStatusRevoked {
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
		cacert, err := s.lamassuCAClient.GetCAByID(ctx, serviceV3.GetCAByIDInput{
			CAID: dms.IdentityProfile.EnrollmentSettings.AuthorizedCA,
		})
		if err != nil {
			log.Warn(fmt.Sprintf("could not get authorized %s CA: ", dms.IdentityProfile.EnrollmentSettings.AuthorizedCA), err)
		} else {
			cas = append(cas, (*x509.Certificate)(cacert.Certificate.Certificate))
		}
	}

	if dms.IdentityProfile.CADistributionSettings.IncludeBootstrapCAs {
		for _, bootstrapCA := range dms.IdentityProfile.EnrollmentSettings.BootstrapCAs {
			cacert, err := s.lamassuCAClient.GetCAByID(ctx, serviceV3.GetCAByIDInput{
				CAID: bootstrapCA,
			})
			if err != nil {
				log.Warn(fmt.Sprintf("could not get bootstrap %s CA: ", bootstrapCA), err)
			} else {
				cas = append(cas, (*x509.Certificate)(cacert.Certificate.Certificate))
			}
		}
	}

	for _, ca := range dms.IdentityProfile.CADistributionSettings.ManagedCAs {
		cacert, err := s.lamassuCAClient.GetCAByID(ctx, serviceV3.GetCAByIDInput{
			CAID: ca,
		})
		if err != nil {
			log.Warn(fmt.Sprintf("could not get bootstrap %s CA: ", ca), err)
		} else {
			cas = append(cas, (*x509.Certificate)(cacert.Certificate.Certificate))
		}
	}

	for _, ca := range dms.IdentityProfile.CADistributionSettings.StaticCAs {
		cas = append(cas, ca.Certificate)
	}

	return cas, nil
}

func (s *DMSManagerService) Enroll(ctx context.Context, csr *x509.CertificateRequest, clientCertificateChain []*x509.Certificate, aps string) (*x509.Certificate, error) {
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

	if len(clientCertificateChain) == 0 {
		return nil, &estErrors.GenericError{
			Message:    "no certificate in TLS connection",
			StatusCode: 401,
		}
	}
	log.Debugf("leaf certificate has cn: %s and issuer with CN: %s", clientCertificateChain[0].Subject.CommonName, clientCertificateChain[0].Issuer.CommonName)
	log.Debugf("enroll request has %d certificates in chain (including leaf cert). Configured validation level is %d", len(clientCertificateChain), dms.DeviceManufacturingService.IdentityProfile.EnrollmentSettings.ChainValidationLevel)
	maxChainValidationDepth := dms.DeviceManufacturingService.IdentityProfile.EnrollmentSettings.ChainValidationLevel

	allowEnrollment := false
	for _, validationCAName := range dms.DeviceManufacturingService.IdentityProfile.EnrollmentSettings.BootstrapCAs {
		validationCA, err := s.lamassuCAClient.GetCAByID(ctx, serviceV3.GetCAByIDInput{CAID: validationCAName})
		if err != nil {
			log.Errorf("could not get CA from lamassu. Skipping to next Validation CA: %s", err)
			continue
		}

		log.Debugf("checking chain using CA with %s (and cn: %s)", validationCA.ID, validationCA.Subject.CommonName)
		//Check if CA has chain or just leaf
		if len(clientCertificateChain) == 1 {
			//Only leaf. Validate with Validation CA
			chain := []*x509.Certificate{
				clientCertificateChain[0],
				(*x509.Certificate)(validationCA.Certificate.Certificate),
			}
			validChain := verifyChain(chain)
			if !validChain {
				log.Warnf("Validation CA did not issue presented crt")
			} else {
				log.Warnf("Validation CA did issue presented crt. Allowing Enrollment")
				allowEnrollment = true
				break
			}
		} else {
			//Last certificate in chain should be either Validation CA itself or direct intermediate CA issued by Validation CA
			chain := clientCertificateChain
			if maxChainValidationDepth == -1 {
				log.Debugf("validating entire chain")
			} else {
				if len(clientCertificateChain) < maxChainValidationDepth {
					log.Debugf("validating entire chain. %d presented certificates", len(chain))
				} else {
					log.Debugf("validation will ONLY consider first %d certificates in chain. The remaining %d certificates will not be considered", maxChainValidationDepth, len(chain)-maxChainValidationDepth)
					//get first maxChainValidationDepth certificates in chain
					chain = clientCertificateChain[:maxChainValidationDepth]
				}
			}
			validChain := verifyChain(chain)
			if !validChain {
				log.Warnf("Tampered chain. Rejecting enrollment")
				return nil, &estErrors.GenericError{
					Message:    "tampered TLS chain",
					StatusCode: 401,
				}
			}
			//Check if last certificate in chain is VAlidation CA
			lastCrtInChain := chain[len(chain)-1]
			if slices.Compare[byte](lastCrtInChain.Raw, validationCA.Certificate.Certificate.Raw) == 0 {
				//lastCrtInChain is Validation CA. Allow Enrollment
				log.Debug("Validation CA is in the chain. Allowing Enrollment")
				allowEnrollment = true
				break
			} else {
				log.Debug("Validation CA is not in the chain. Check if last crt in chain was issued by Validation CA")
				//Check if lastCrtInChain signature was generated by Validation CA
				err = lastCrtInChain.CheckSignatureFrom((*x509.Certificate)(validationCA.Certificate.Certificate))
				if err != nil {
					log.Debug("Last considered (considering DMS chain level verification parameter) certificate in chain was not issued by Validation CA")
				} else {
					log.Debug("Last considered (considering DMS chain level verification parameter) certificate in chain was issued by Validation CA. Allowing Enrollment")
					allowEnrollment = true
					break
				}
			}

		}
	}

	if !allowEnrollment {
		log.Info("no Validation CA allowed the enrollment. Rejecting request")
		return nil, &estErrors.GenericError{
			Message:    "client certificate " + clientCertificateChain[len(clientCertificateChain)-1].Subject.CommonName + " is not valid",
			StatusCode: 401,
		}
	}

	if dms.IdentityProfile.EnrollmentSettings.RegistrationMode == api.JITP {
		log.Debugf("DMS is configured with JustInTime registration. will create device with ID %s", csr.Subject.CommonName)
		_, err = s.lamassuDevManagerClient.CreateDevice(ctx, csr.Subject.CommonName, csr.Subject.CommonName, aps, "-", dms.IdentityProfile.EnrollmentSettings.Tags, dms.IdentityProfile.EnrollmentSettings.Icon, dms.IdentityProfile.EnrollmentSettings.Color)
		if err != nil {
			log.Error(fmt.Sprintf("something went wrong while registering the device: %s", err))
			return nil, err
		}
		log.Debugf("device registered")
	} else if dms.IdentityProfile.EnrollmentSettings.RegistrationMode == api.PreRegistration {
		log.Debugf("DMS is configured with PreRegistration. will check device with ID %s", csr.Subject.CommonName)
		_, err := s.lamassuDevManagerClient.GetDeviceById(ctx, csr.Subject.CommonName)
		if err != nil {
			log.Error(fmt.Sprintf("something went wrong while checking device: %s", err))
			return nil, err
		}
		log.Debugf("device exists")
	}

	estURL, err := url.Parse(s.DevManagerAddr)
	if err != nil {
		log.Error(fmt.Sprintf("could not parse EST Server URL: %s", err))
		return nil, err
	}

	estClient, err := lamassuEstClient.NewESTClient(nil, estURL, []*x509.Certificate{s.UpstreamCert}, s.UpstreamKey, nil, true)
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
	caCert, err := s.lamassuCAClient.GetCAByID(ctx, serviceV3.GetCAByIDInput{
		CAID: dms.DeviceManufacturingService.IdentityProfile.EnrollmentSettings.AuthorizedCA,
	})
	if err != nil {
		return nil, err
	}

	if time.Since(cert.NotAfter) > 0 && !dms.DeviceManufacturingService.IdentityProfile.ReerollmentSettings.AllowExpiredRenewal {
		log.Debug("certificate is expired and DMS does not allow expired renewals")
		return nil, &estErrors.GenericError{
			Message:    "certificate is expired",
			StatusCode: 403,
		}
	}

	authorizeReenroll := false
	rootPool := x509.NewCertPool()
	rootPool.AddCert((*x509.Certificate)(caCert.Certificate.Certificate))
	_, err = cert.Verify(x509.VerifyOptions{Roots: rootPool})
	if err != nil {
		log.Debugf("could not verify certificate with Authorized CA: %s", err)
		if len(dms.IdentityProfile.ReerollmentSettings.AdditionaValidationCAs) > 0 {
			log.Debug("attempting validation with additional Validation CAs")
			for _, extraValCAID := range dms.IdentityProfile.ReerollmentSettings.AdditionaValidationCAs {
				extraValCA, err := s.lamassuCAClient.GetCAByID(ctx, serviceV3.GetCAByIDInput{CAID: extraValCAID})
				if err != nil {
					log.Errorf("could not get lamassu CA: %s", err)
					continue
				}
				rootPool := x509.NewCertPool()
				rootPool.AddCert((*x509.Certificate)(extraValCA.Certificate.Certificate))
				_, err = cert.Verify(x509.VerifyOptions{Roots: rootPool})
				if err != nil {
					log.Debugf("could not verify certificate with Additional Validation CA with ID %s and CN %s: %s", extraValCA.ID, extraValCA.Subject.CommonName, err)
				} else {
					log.Debugf("Additional Validation CA with ID %s and CN %s authorizes enrollment", extraValCA.ID, extraValCA.Subject.CommonName)
					authorizeReenroll = true
					break
				}
			}
		}
	} else {
		log.Debugf("Authorized CA allows ReEnrollment")
		authorizeReenroll = true
	}

	if !authorizeReenroll {
		return nil, &estErrors.GenericError{
			Message:    "client certificate is not valid",
			StatusCode: 403,
		}
	}

	estURL, err := url.Parse(s.DevManagerAddr)
	if err != nil {
		log.Error(fmt.Sprintf("could not parse EST Server URL: %s", err))
		return nil, err
	}

	estClient, err := lamassuEstClient.NewESTClient(nil, estURL, []*x509.Certificate{s.UpstreamCert}, s.UpstreamKey, nil, true)
	if err != nil {
		return nil, err
	}

	ctx = context.WithValue(ctx, "dmsName", dms.DeviceManufacturingService.Name)
	deviceNewCert, err := estClient.Reenroll(ctx, csr, aps)

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

// first crt in chain Is the leaf crt. Chain should have at least 2 certificates
func verifyChain(chain []*x509.Certificate) bool {
	lFunc := log.WithField("svc", "Verify Chain")

	for i := 0; i < len(chain)-1; i++ {
		lFunc.Debugf("chain validation round %d/%d", i+1, len(chain)-1)
		roots := x509.NewCertPool()
		roots.AddCert(chain[i+1])

		lFunc.Debugf("root certificate has CN %s and issuer CN %s", chain[i+1].Subject.CommonName, chain[i+1].Issuer.CommonName)
		lFunc.Debugf("certificate has CN %s and issuer CN %s", chain[i].Subject.CommonName, chain[i].Issuer.CommonName)

		leaf := chain[i]

		opts := x509.VerifyOptions{
			Roots: roots,
		}

		if _, err := leaf.Verify(opts); err != nil {
			log.Debugf("chain validation err: %s", err)
			return false
		}
	}

	return true
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
