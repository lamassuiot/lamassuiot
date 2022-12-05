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

	"github.com/go-kit/kit/log"
	lamassuCAClient "github.com/lamassuiot/lamassuiot/pkg/ca/client"
	lamassuCAApi "github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/common/api"
	dmsErrors "github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/errors"
	dmsRepository "github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/repository"
	"github.com/lamassuiot/lamassuiot/pkg/utils"
	"golang.org/x/exp/slices"
)

type Service interface {
	Health(ctx context.Context) bool
	CreateDMS(ctx context.Context, input *api.CreateDMSInput) (*api.CreateDMSOutput, error)
	CreateDMSWithCertificateRequest(ctx context.Context, input *api.CreateDMSWithCertificateRequestInput) (*api.CreateDMSWithCertificateRequestOutput, error)
	UpdateDMSStatus(ctx context.Context, input *api.UpdateDMSStatusInput) (*api.UpdateDMSStatusOutput, error)
	UpdateDMSAuthorizedCAs(ctx context.Context, input *api.UpdateDMSAuthorizedCAsInput) (*api.UpdateDMSAuthorizedCAsOutput, error)
	GetDMSs(ctx context.Context, input *api.GetDMSsInput) (*api.GetDMSsOutput, error)
	GetDMSByName(ctx context.Context, input *api.GetDMSByNameInput) (*api.GetDMSByNameOutput, error)
}

type dmsManagerContext struct {
	dmsRepository   dmsRepository.DeviceManufacturingServiceRepository
	lamassuCAClient lamassuCAClient.LamassuCAClient
	logger          log.Logger
}

func NewDMSManagerService(dmsRepo dmsRepository.DeviceManufacturingServiceRepository, client *lamassuCAClient.LamassuCAClient) Service {
	return &dmsManagerContext{
		dmsRepository:   dmsRepo,
		lamassuCAClient: *client,
	}
}

func (s *dmsManagerContext) Health(ctx context.Context) bool {
	return true
}

func (s *dmsManagerContext) CreateDMS(ctx context.Context, input *api.CreateDMSInput) (*api.CreateDMSOutput, error) {
	subject := pkix.Name{
		CommonName:         input.Subject.CommonName,
		Country:            []string{input.Subject.Country},
		Province:           []string{input.Subject.State},
		Locality:           []string{input.Subject.Locality},
		Organization:       []string{input.Subject.Organization},
		OrganizationalUnit: []string{input.Subject.OrganizationUnit},
	}

	var privateKey interface{}
	if input.KeyMetadata.KeyType == api.RSA {
		rsaKey, _ := rsa.GenerateKey(rand.Reader, input.KeyMetadata.KeyBits)
		privateKey = rsaKey
	} else {
		var curve elliptic.Curve
		switch input.KeyMetadata.KeyBits {
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
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return &api.CreateDMSOutput{}, err
	}

	createDMSWithCSROutput, err := s.CreateDMSWithCertificateRequest(ctx, &api.CreateDMSWithCertificateRequestInput{
		CertificateRequest: csr,
	})
	if err != nil {
		return &api.CreateDMSOutput{}, err
	}

	return &api.CreateDMSOutput{
		DMS:        createDMSWithCSROutput.DeviceManufacturingService,
		PrivateKey: privateKey,
	}, nil
}

func (s *dmsManagerContext) CreateDMSWithCertificateRequest(ctx context.Context, input *api.CreateDMSWithCertificateRequestInput) (*api.CreateDMSWithCertificateRequestOutput, error) {
	err := s.dmsRepository.Insert(ctx, input.CertificateRequest)
	if err != nil {
		return &api.CreateDMSWithCertificateRequestOutput{}, err
	}

	dms, err := s.GetDMSByName(ctx, &api.GetDMSByNameInput{
		Name: input.CertificateRequest.Subject.CommonName,
	})
	if err != nil {
		return &api.CreateDMSWithCertificateRequestOutput{}, err
	}

	return &api.CreateDMSWithCertificateRequestOutput{
		DeviceManufacturingService: dms.DeviceManufacturingService,
	}, nil
}

func (s *dmsManagerContext) UpdateDMSStatus(ctx context.Context, input *api.UpdateDMSStatusInput) (*api.UpdateDMSStatusOutput, error) {
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

	dmsOutput, err := s.GetDMSByName(ctx, &api.GetDMSByNameInput{
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
		if dms.X509Asset.IsCertificate {
			return &api.UpdateDMSStatusOutput{}, errors.New("DMS already has a certificate, cannot be approved")
		}
		dms.Status = api.DMSStatusApproved
		signOutput, err := s.lamassuCAClient.SignCertificateRequest(ctx, &lamassuCAApi.SignCertificateRequestInput{
			CAType:                    lamassuCAApi.CATypeDMSEnroller,
			CAName:                    "LAMASSU-DMS-MANAGER",
			CertificateSigningRequest: dms.X509Asset.CertificateRequest,
			SignVerbatim:              true,
		})
		if err != nil {
			return &api.UpdateDMSStatusOutput{}, err
		}

		dms.SerialNumber = utils.InsertNth(utils.ToHexInt(signOutput.Certificate.SerialNumber), 2)
		dms.X509Asset = api.X509Asset{
			Certificate:        signOutput.Certificate,
			IsCertificate:      true,
			CertificateRequest: nil,
		}

		err = s.dmsRepository.UpdateDMS(ctx, dms)
		if err != nil {
			return &api.UpdateDMSStatusOutput{}, err
		}

	case api.DMSStatusRevoked:
		if !dms.X509Asset.IsCertificate {
			return &api.UpdateDMSStatusOutput{}, errors.New("DMS already has no active certificate, cannot be revoked")
		}

		_, err = s.lamassuCAClient.RevokeCertificate(ctx, &lamassuCAApi.RevokeCertificateInput{
			CAType:                  lamassuCAApi.CATypeDMSEnroller,
			CAName:                  "LAMASSU-DMS-MANAGER",
			CertificateSerialNumber: dms.SerialNumber,
			RevocationReason:        "Manually revoked by DMS manager",
		})
		if err != nil {
			return &api.UpdateDMSStatusOutput{}, err
		}

		err = s.dmsRepository.UpdateStatus(ctx, dms.Name, api.DMSStatusRevoked)
		if err != nil {
			return &api.UpdateDMSStatusOutput{}, err
		}
	default:
		err := s.dmsRepository.UpdateStatus(ctx, input.Name, input.Status)
		if err != nil {
			return &api.UpdateDMSStatusOutput{}, err
		}
	}

	getDMSOutput, err := s.GetDMSByName(ctx, &api.GetDMSByNameInput{
		Name: input.Name,
	})
	if err != nil {
		return &api.UpdateDMSStatusOutput{}, err
	}

	return &api.UpdateDMSStatusOutput{
		DeviceManufacturingService: getDMSOutput.DeviceManufacturingService,
	}, nil
}

func (s *dmsManagerContext) GetDMSs(ctx context.Context, input *api.GetDMSsInput) (*api.GetDMSsOutput, error) {
	totalDMS, dmsS, err := s.dmsRepository.SelectAll(ctx, input.QueryParameters)
	if err != nil {
		return &api.GetDMSsOutput{}, err
	}

	var dmsList []api.DeviceManufacturingService
	for _, v := range dmsS {
		dmsOutput, err := s.GetDMSByName(ctx, &api.GetDMSByNameInput{
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

func (s *dmsManagerContext) UpdateDMSAuthorizedCAs(ctx context.Context, input *api.UpdateDMSAuthorizedCAsInput) (*api.UpdateDMSAuthorizedCAsOutput, error) {
	dmsOutput, err := s.GetDMSByName(ctx, &api.GetDMSByNameInput{
		Name: input.Name,
	})
	if err != nil {
		return &api.UpdateDMSAuthorizedCAsOutput{}, err
	}

	err = s.dmsRepository.UpdateAuthorizedCAs(ctx, input.Name, input.AuthorizedCAs)
	if err != nil {
		return &api.UpdateDMSAuthorizedCAsOutput{}, err
	}

	dmsOutput, err = s.GetDMSByName(ctx, &api.GetDMSByNameInput{
		Name: input.Name,
	})
	if err != nil {
		return &api.UpdateDMSAuthorizedCAsOutput{}, err
	}

	return &api.UpdateDMSAuthorizedCAsOutput{
		DeviceManufacturingService: dmsOutput.DeviceManufacturingService,
	}, nil
}

func (s *dmsManagerContext) GetDMSByName(ctx context.Context, input *api.GetDMSByNameInput) (*api.GetDMSByNameOutput, error) {
	dms, err := s.dmsRepository.SelectByName(ctx, input.Name)
	if err != nil {
		return &api.GetDMSByNameOutput{}, err
	}

	if dms.Status != api.DMSStatusPendingApproval && dms.Status != api.DMSStatusRejected {
		caOutput, err := s.lamassuCAClient.GetCertificateBySerialNumber(ctx, &lamassuCAApi.GetCertificateBySerialNumberInput{
			CAType:                  lamassuCAApi.CATypeDMSEnroller,
			CAName:                  "LAMASSU-DMS-MANAGER",
			CertificateSerialNumber: dms.SerialNumber,
		})
		if err != nil {
			return &api.GetDMSByNameOutput{}, err
		}

		if caOutput.Status == lamassuCAApi.StatusExpired && dms.Status != api.DMSStatusExpired {
			output, err := s.UpdateDMSStatus(ctx, &api.UpdateDMSStatusInput{
				Name:   dms.Name,
				Status: api.DMSStatusExpired,
			})
			if err != nil {
				return &api.GetDMSByNameOutput{}, err
			}

			dms = output.DeviceManufacturingService
		} else if caOutput.Status == lamassuCAApi.StatusRevoked && dms.Status != api.DMSStatusRevoked {
			output, err := s.UpdateDMSStatus(ctx, &api.UpdateDMSStatusInput{
				Name:   dms.Name,
				Status: api.DMSStatusRevoked,
			})
			if err != nil {
				return &api.GetDMSByNameOutput{}, err
			}

			dms = output.DeviceManufacturingService
		}
	}

	keyType, keyBits, keyStrength := getPublicKeyInfo(dms.X509Asset)
	dms.KeyMetadata = api.KeyStrengthMetadata{
		KeyType:     keyType,
		KeyBits:     keyBits,
		KeyStrength: keyStrength,
	}

	return &api.GetDMSByNameOutput{
		DeviceManufacturingService: dms,
	}, nil
}

func getPublicKeyInfo(x509Asset api.X509Asset) (api.KeyType, int, api.KeyStrength) {
	var keyBits int
	var keyType api.KeyType

	if x509Asset.IsCertificate {
		keyType = api.ParseKeyType(x509Asset.Certificate.PublicKeyAlgorithm.String())
		switch keyType {
		case api.RSA:
			keyBits = x509Asset.Certificate.PublicKey.(*rsa.PublicKey).N.BitLen()
		case api.ECDSA:
			keyBits = x509Asset.Certificate.PublicKey.(*ecdsa.PublicKey).Params().BitSize
		}
	} else {
		keyType = api.ParseKeyType(x509Asset.CertificateRequest.PublicKeyAlgorithm.String())
		switch keyType {
		case api.RSA:
			keyBits = x509Asset.CertificateRequest.PublicKey.(*rsa.PublicKey).N.BitLen()
		case api.ECDSA:
			keyBits = x509Asset.CertificateRequest.PublicKey.(*ecdsa.PublicKey).Params().BitSize
		}
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
