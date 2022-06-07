package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"sync"

	"github.com/go-kit/kit/log"
	"github.com/jakehl/goid"
	lamassucaclient "github.com/lamassuiot/lamassuiot/pkg/ca/client"
	caDTO "github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/dms-enroller/common/dto"
	dmsErrors "github.com/lamassuiot/lamassuiot/pkg/dms-enroller/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/dms-enroller/server/models/dms"
	dmsstore "github.com/lamassuiot/lamassuiot/pkg/dms-enroller/server/models/dms/store"
	"github.com/lamassuiot/lamassuiot/pkg/utils"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"
)

type Service interface {
	Health(ctx context.Context) bool
	CreateDMS(ctx context.Context, csrBase64Encoded string, dmsName string) (dto.DMS, error)
	CreateDMSForm(ctx context.Context, subject dto.Subject, PrivateKeyMetadata dto.PrivateKeyMetadata, dmsName string) (string, dto.DMS, error)
	UpdateDMSStatus(ctx context.Context, status string, id string, CAList []string) (dto.DMS, error)
	DeleteDMS(ctx context.Context, id string) error
	GetDMSs(ctx context.Context, queryParameters filters.QueryParameters) ([]dto.DMS, int, error)
	GetDMSbyID(ctx context.Context, id string) (dto.DMS, error)
}

type enrollerService struct {
	mtx        sync.RWMutex
	dmsDBStore dmsstore.DB
	//	devicesDb       devicesStore.DB
	lamassuCaClient lamassucaclient.LamassuCaClient
	logger          log.Logger
}

func NewEnrollerService(dmsDbStore dmsstore.DB, lamassuCa *lamassucaclient.LamassuCaClient, logger log.Logger) Service {
	return &enrollerService{
		dmsDBStore:      dmsDbStore,
		lamassuCaClient: *lamassuCa,
		logger:          logger,
	}
}

func (s *enrollerService) Health(ctx context.Context) bool {
	return true
}

func (s *enrollerService) CreateDMS(ctx context.Context, csrBase64Encoded string, dmsName string) (dto.DMS, error) {

	//csrBase64Encoded
	decodedCsr, _ := utils.DecodeB64(csrBase64Encoded)

	p, _ := pem.Decode([]byte(decodedCsr))

	csr, _ := x509.ParseCertificateRequest(p.Bytes)

	keyType, keyBits := getPublicKeyInfo(csr)

	d := dto.DMS{
		Id:        goid.NewV4UUID().String(),
		Name:      dmsName,
		CsrBase64: csrBase64Encoded,
		Status:    dms.PendingStatus,
		KeyMetadata: dto.PrivateKeyMetadataWithStregth{
			KeyType: keyType,
			KeyBits: keyBits,
		},

		EnrolledDevices: 0,
	}

	dmsId, _ := s.dmsDBStore.Insert(ctx, d)

	return s.dmsDBStore.SelectByID(ctx, dmsId)
}

func (s *enrollerService) CreateDMSForm(ctx context.Context, subject dto.Subject, PrivateKeyMetadata dto.PrivateKeyMetadata, dmsName string) (string, dto.DMS, error) {
	subj := pkix.Name{
		CommonName:         subject.CN,
		Country:            []string{subject.C},
		Province:           []string{subject.ST},
		Locality:           []string{subject.L},
		Organization:       []string{subject.O},
		OrganizationalUnit: []string{subject.OU},
	}

	if PrivateKeyMetadata.KeyType == "RSA" {
		privKey, _ := rsa.GenerateKey(rand.Reader, PrivateKeyMetadata.KeyBits)
		csrBytes, _ := generateCSR(ctx, PrivateKeyMetadata.KeyType, PrivateKeyMetadata.KeyBits, privKey, subj)
		csrEncoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

		privkey_bytes := x509.MarshalPKCS1PrivateKey(privKey)
		privkey_pem := string(pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: privkey_bytes,
			},
		))
		privkey_pemByte := utils.EncodeB64([]byte(privkey_pem))
		csr, _ := s.CreateDMS(ctx, string(utils.EncodeB64(csrEncoded)), dmsName)

		return string(privkey_pemByte), csr, nil

	} else {
		var priv *ecdsa.PrivateKey
		switch PrivateKeyMetadata.KeyBits {
		case 224:
			priv, _ = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		case 256:
			priv, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case 384:
			priv, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		}
		privkey_bytesm, _ := x509.MarshalPKCS8PrivateKey(priv)
		privkey_pem := string(pem.EncodeToMemory(
			&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: privkey_bytesm,
			},
		))
		privkey_pemByte := utils.EncodeB64([]byte(privkey_pem))
		csrBytes, _ := generateCSR(ctx, PrivateKeyMetadata.KeyType, PrivateKeyMetadata.KeyBits, priv, subj)
		csrEncoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
		csr, _ := s.CreateDMS(ctx, string(utils.EncodeB64(csrEncoded)), dmsName)

		return string(privkey_pemByte), csr, nil

	}
}

func generateCSR(ctx context.Context, keyType string, keyBits int, priv interface{}, subj pkix.Name) ([]byte, error) {
	var signingAlgorithm x509.SignatureAlgorithm
	if keyType == "EC" {
		signingAlgorithm = x509.ECDSAWithSHA512
	} else {
		signingAlgorithm = x509.SHA512WithRSA
	}
	rawSubj := subj.ToRDNSequence()
	/*rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
		{Type: oidEmailAddress, Value: emailAddress},
	})*/

	asn1Subj, _ := asn1.Marshal(rawSubj)
	template := x509.CertificateRequest{
		RawSubject: asn1Subj,
		//EmailAddresses:     []string{emailAddress},
		SignatureAlgorithm: signingAlgorithm,
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, priv)
	return csrBytes, err
}

func (s *enrollerService) UpdateDMSStatus(ctx context.Context, DMSstatus string, id string, CAList []string) (dto.DMS, error) {
	var err error
	var d dto.DMS
	prevDms, err := s.dmsDBStore.SelectByID(ctx, id)
	if err != nil {
		return dto.DMS{}, err
	}

	switch status := DMSstatus; status {
	case dms.ApprovedStatus:
		if prevDms.Status == dms.PendingStatus {
			b, _ := utils.DecodeB64(prevDms.CsrBase64)
			csrBytes, _ := pem.Decode([]byte(b))
			csr, _ := x509.ParseCertificateRequest(csrBytes.Bytes)
			crt, _ := s.ApprobeCSR(ctx, id, csr)
			err = s.dmsDBStore.InsertAuthorizedCAs(ctx, id, CAList)
			if err != nil {
				return dto.DMS{}, err
			}
			d, _ = s.dmsDBStore.UpdateByID(ctx, id, dms.ApprovedStatus, utils.InsertNth(utils.ToHexInt(crt.SerialNumber), 2), "")

			var cb []byte
			cb = append(cb, crt.Raw...)
			certificate := pem.Block{Type: "CERTIFICATE", Bytes: cb}
			cert := pem.EncodeToMemory(&certificate)

			d.CerificateBase64 = string(utils.EncodeB64(cert))

		} else {
			return dto.DMS{}, &dmsErrors.GenericError{
				Message:    "The DMS Status is not PENDING_APPROVAL",
				StatusCode: 412,
			}
		}
	case dms.RevokedStatus:
		if prevDms.Status == dms.ApprovedStatus {
			d, _ = s.dmsDBStore.UpdateByID(ctx, id, dms.RevokedStatus, prevDms.SerialNumber, "")
			_ = s.RevokeCert(ctx, prevDms.SerialNumber)
			_ = s.dmsDBStore.DeleteAuthorizedCAs(ctx, id)
		} else {
			return dto.DMS{}, &dmsErrors.GenericError{
				Message:    "The DMS Status is not APPROVED",
				StatusCode: 412,
			}
		}
	case dms.DeniedStatus:
		if prevDms.Status == dms.PendingStatus {
			d, _ = s.dmsDBStore.UpdateByID(ctx, id, dms.DeniedStatus, "", "")
		} else {
			return dto.DMS{}, &dmsErrors.GenericError{
				Message:    "The DMS Status is not PENDING_APPROVAL",
				StatusCode: 412,
			}
		}
	default:
		return dto.DMS{}, &dmsErrors.GenericError{
			Message:    "The Status is PENDING_APPROVAL",
			StatusCode: 412,
		}
	}

	return d, nil
}

func (s *enrollerService) RevokeCert(ctx context.Context, serialToRevoke string) error {
	caType, err := caDTO.ParseCAType("dmsenroller")
	// revocar llamando a lamassu CA
	err = s.lamassuCaClient.RevokeCert(ctx, caType, "Lamassu-DMS-Enroller", serialToRevoke)
	return err
}

func (s *enrollerService) ApprobeCSR(ctx context.Context, id string, csr *x509.CertificateRequest) (*x509.Certificate, error) {
	caType, err := caDTO.ParseCAType("dmsenroller")
	crt, _, err := s.lamassuCaClient.SignCertificateRequest(ctx, caType, "Lamassu-DMS-Enroller", csr, false, id)
	if err != nil {
		return &x509.Certificate{}, err
	}

	return crt, nil
}

func (s *enrollerService) DeleteDMS(ctx context.Context, id string) error {
	d, err := s.dmsDBStore.SelectByID(ctx, id)
	if err != nil {
		return err
	}
	if d.Status == dms.DeniedStatus || d.Status == dms.RevokedStatus {
		_ = s.dmsDBStore.Delete(ctx, id)
		if d.Status == dms.RevokedStatus {
			_ = s.dmsDBStore.DeleteAuthorizedCAs(ctx, id)
		}
	} else {
		return &dmsErrors.GenericError{
			Message:    "The DMS Status is " + d.Status,
			StatusCode: 412,
		}
	}
	return err
}
func (s *enrollerService) GetDMSs(ctx context.Context, queryParameters filters.QueryParameters) ([]dto.DMS, int, error) {
	caType, err := caDTO.ParseCAType("dmsenroller")
	d, totalDMS, err := s.dmsDBStore.SelectAll(ctx, queryParameters)
	if err != nil {
		return []dto.DMS{}, 0, err
	}
	var dmsList []dto.DMS = make([]dto.DMS, 0)
	for _, item := range d {
		lamassuCert, _ := s.lamassuCaClient.GetCert(ctx, caType, "Lamassu-DMS-Enroller", item.SerialNumber)
		item.Subject = dto.Subject{
			C:  lamassuCert.Subject.Country,
			ST: lamassuCert.Subject.State,
			L:  lamassuCert.Subject.Locality,
			O:  lamassuCert.Subject.Organization,
			OU: lamassuCert.Subject.OrganizationUnit,
			CN: lamassuCert.Subject.CommonName,
		}
		item.CerificateBase64 = lamassuCert.CertContent.CerificateBase64
		//	item.EnrolledDevices, err = s.devicesDb.CountDevicesByDmsId(ctx, item.Id)
		if item.Status == "APPROVED" {
			CAs, _ := s.dmsDBStore.SelectByDMSIDAuthorizedCAs(ctx, item.Id)
			for _, ca := range CAs {
				item.AuthorizedCAs = append(item.AuthorizedCAs, ca.CaName)
			}
		}
		dmsList = append(dmsList, item)
	}

	return dmsList, totalDMS, nil
}

func (s *enrollerService) GetDMSbyID(ctx context.Context, id string) (dto.DMS, error) {
	caType, err := caDTO.ParseCAType("dmsenroller")
	d, err := s.dmsDBStore.SelectByID(ctx, id)
	//d.EnrolledDevices, err = s.devicesDb.CountDevicesByDmsId(ctx, id)
	if err != nil {
		return dto.DMS{}, err
	}
	lamassuCert, _ := s.lamassuCaClient.GetCert(ctx, caType, "Lamassu-DMS-Enroller", d.SerialNumber)
	d.Subject = dto.Subject{
		C:  lamassuCert.Subject.Country,
		ST: lamassuCert.Subject.State,
		L:  lamassuCert.Subject.Locality,
		O:  lamassuCert.Subject.Organization,
		OU: lamassuCert.Subject.OrganizationUnit,
		CN: lamassuCert.Subject.CommonName,
	}
	d.CerificateBase64 = lamassuCert.CertContent.CerificateBase64
	if d.Status == "APPROVED" {
		CAs, _ := s.dmsDBStore.SelectByDMSIDAuthorizedCAs(ctx, d.Id)
		for _, ca := range CAs {
			d.AuthorizedCAs = append(d.AuthorizedCAs, ca.CaName)
		}
	}
	return d, nil
}

func getPublicKeyInfo(cert *x509.CertificateRequest) (string, int) {
	key := cert.PublicKeyAlgorithm.String()
	var keyBits int
	switch key {
	case "RSA":
		keyBits = cert.PublicKey.(*rsa.PublicKey).N.BitLen()
		return "RSA", keyBits
	case "ECDSA":
		keyBits = cert.PublicKey.(*ecdsa.PublicKey).Params().BitSize
		return "EC", keyBits
	}

	return "UNKOWN_KEY_TYPE", -1
}
