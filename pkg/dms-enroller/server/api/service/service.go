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
	"errors"
	"sync"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/jakehl/goid"
	lamassucaclient "github.com/lamassuiot/lamassuiot/pkg/ca/client"
	caDTO "github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/utils"

	//devicesStore "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/models/device/store"
	"github.com/lamassuiot/lamassuiot/pkg/dms-enroller/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/dms-enroller/server/models/dms"
	dmsstore "github.com/lamassuiot/lamassuiot/pkg/dms-enroller/server/models/dms/store"
)

type Service interface {
	Health(ctx context.Context) bool
	CreateDMS(ctx context.Context, csrBase64Encoded string, dmsName string) (dto.DMS, error)
	CreateDMSForm(ctx context.Context, subject dto.Subject, PrivateKeyMetadata dto.PrivateKeyMetadata, dmsName string) (string, dto.DMS, error)
	UpdateDMSStatus(ctx context.Context, status string, id string, CAList []string) (dto.DMS, error)
	DeleteDMS(ctx context.Context, id string) error
	GetDMSs(ctx context.Context) ([]dto.DMS, error)
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
	decodedCsr, err := utils.DecodeB64(csrBase64Encoded)
	if err != nil {
		return dto.DMS{}, err
	}

	p, _ := pem.Decode([]byte(decodedCsr))

	csr, err := x509.ParseCertificateRequest(p.Bytes)
	if err != nil {
		return dto.DMS{}, err
	}

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

	dmsId, err := s.dmsDBStore.Insert(ctx, d)

	if err != nil {
		return dto.DMS{}, err
	}

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
		csrBytes, err := generateCSR(ctx, PrivateKeyMetadata.KeyType, PrivateKeyMetadata.KeyBits, privKey, subj)
		if err != nil {
			return "", dto.DMS{}, err
		}

		csrEncoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

		privkey_bytes := x509.MarshalPKCS1PrivateKey(privKey)
		privkey_pem := string(pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: privkey_bytes,
			},
		))
		privkey_pem = utils.EcodeB64(privkey_pem)
		csr, err := s.CreateDMS(ctx, utils.EcodeB64(string(csrEncoded)), dmsName)
		if err != nil {
			return "", dto.DMS{}, err
		} else {
			return privkey_pem, csr, nil
		}
	} else if PrivateKeyMetadata.KeyType == "ec" {
		var priv *ecdsa.PrivateKey
		var err error
		switch PrivateKeyMetadata.KeyBits {
		case 224:
			priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		case 256:
			priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case 384:
			priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		case 521:
			priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		default:
			err = errors.New("Unsupported key length")
		}
		if err != nil {
			level.Debug(s.logger).Log("err", err)
			return "", dto.DMS{}, err
		}
		privkey_bytesm, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			level.Debug(s.logger).Log("err", err)
			return "", dto.DMS{}, err
		}
		privkey_pem := string(pem.EncodeToMemory(
			&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: privkey_bytesm,
			},
		))
		privkey_pem = utils.EcodeB64(privkey_pem)
		csrBytes, err := generateCSR(ctx, PrivateKeyMetadata.KeyType, PrivateKeyMetadata.KeyBits, priv, subj)
		if err != nil {
			level.Debug(s.logger).Log("err", err)
			return "", dto.DMS{}, err
		}
		csrEncoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
		csr, err := s.CreateDMS(ctx, utils.EcodeB64(string(csrEncoded)), dmsName)
		if err != nil {
			level.Debug(s.logger).Log("err", err)
			return "", dto.DMS{}, err
		} else {
			return privkey_pem, csr, nil
		}
	} else {
		return "", dto.DMS{}, errors.New("Invalid key format")
	}
}

func generateCSR(ctx context.Context, keyType string, keyBits int, priv interface{}, subj pkix.Name) ([]byte, error) {
	var signingAlgorithm x509.SignatureAlgorithm
	if keyType == "ec" {
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
			b, err := utils.DecodeB64(prevDms.CsrBase64)
			if err != nil {
				return dto.DMS{}, err
			}
			csrBytes, _ := pem.Decode([]byte(b))
			csr, err := x509.ParseCertificateRequest(csrBytes.Bytes)
			if err != nil {
				return dto.DMS{}, err
			}
			crt, err := s.ApprobeCSR(ctx, id, csr)
			if err != nil {
				return dto.DMS{}, err
			}
			err = s.dmsDBStore.InsertAuthorizedCAs(ctx, id, CAList)
			if err != nil {
				return dto.DMS{}, err
			}
			d, err = s.dmsDBStore.UpdateByID(ctx, id, dms.ApprovedStatus, utils.InsertNth(utils.ToHexInt(crt.SerialNumber), 2), "")
			if err != nil {
				s.dmsDBStore.DeleteAuthorizedCAs(ctx, id)
				return dto.DMS{}, err
			}

			var cb []byte
			cb = append(cb, crt.Raw...)
			certificate := pem.Block{Type: "CERTIFICATE", Bytes: cb}
			cert := pem.EncodeToMemory(&certificate)

			d.CerificateBase64 = utils.EcodeB64(string(cert))

		} else {
			return dto.DMS{}, err
		}
	case dms.RevokedStatus:
		if prevDms.Status == dms.ApprovedStatus {
			d, err = s.dmsDBStore.UpdateByID(ctx, id, dms.RevokedStatus, prevDms.SerialNumber, "")
			if err != nil {
				return dto.DMS{}, err
			}
			err = s.RevokeCert(ctx, prevDms.SerialNumber)
			if err != nil {
				return dto.DMS{}, err
			}
			err = s.dmsDBStore.DeleteAuthorizedCAs(ctx, id)
			if err != nil {
				return dto.DMS{}, err
			}
		} else {
			return dto.DMS{}, err
		}
	case dms.DeniedStatus:
		if prevDms.Status == dms.PendingStatus {
			d, err = s.dmsDBStore.UpdateByID(ctx, id, dms.DeniedStatus, "", "")
			if err != nil {
				return dto.DMS{}, err
			}
		} else {
			return dto.DMS{}, err
		}
	default:
		return dto.DMS{}, err
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
	crt, _, err := s.lamassuCaClient.SignCertificateRequest(ctx, caType, "Lamassu-DMS-Enroller", csr, true)
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
		err = s.dmsDBStore.Delete(ctx, id)
		if err != nil {
			return err
		}
		if d.Status == dms.RevokedStatus {
			err = s.dmsDBStore.DeleteAuthorizedCAs(ctx, id)
			if err != nil {
				return err
			}
		}
	}
	return err
}
func (s *enrollerService) GetDMSs(ctx context.Context) ([]dto.DMS, error) {
	caType, err := caDTO.ParseCAType("dmsenroller")
	d, err := s.dmsDBStore.SelectAll(ctx)
	if err != nil {
		return []dto.DMS{}, err
	}
	var dmsList []dto.DMS = make([]dto.DMS, 0)
	for _, item := range d {
		lamassuCert, _ := s.lamassuCaClient.GetCert(ctx, caType, "Lamassu-DMS-Enroller", item.SerialNumber)
		item.Subject = dto.Subject{
			C:  lamassuCert.Subject.C,
			ST: lamassuCert.Subject.ST,
			L:  lamassuCert.Subject.L,
			O:  lamassuCert.Subject.O,
			OU: lamassuCert.Subject.OU,
			CN: lamassuCert.Subject.CN,
		}
		item.CerificateBase64 = lamassuCert.CertContent.CerificateBase64
		//	item.EnrolledDevices, err = s.devicesDb.CountDevicesByDmsId(ctx, item.Id)

		CAs, err := s.dmsDBStore.SelectByDMSIDAuthorizedCAs(ctx, item.Id)
		if err != nil {
			return []dto.DMS{}, err
		}
		for _, ca := range CAs {
			item.AuthorizedCAs = append(item.AuthorizedCAs, ca.CaName)
		}

		dmsList = append(dmsList, item)
	}

	return dmsList, nil
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
		C:  lamassuCert.Subject.C,
		ST: lamassuCert.Subject.ST,
		L:  lamassuCert.Subject.L,
		O:  lamassuCert.Subject.O,
		OU: lamassuCert.Subject.OU,
		CN: lamassuCert.Subject.CN,
	}
	d.CerificateBase64 = lamassuCert.CertContent.CerificateBase64
	CAs, err := s.dmsDBStore.SelectByDMSIDAuthorizedCAs(ctx, d.Id)
	if err != nil {
		return dto.DMS{}, err
	}
	for _, ca := range CAs {
		d.AuthorizedCAs = append(d.AuthorizedCAs, ca.CaName)
	}
	return d, nil
}

func containsRole(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func getPublicKeyInfo(cert *x509.CertificateRequest) (string, int) {
	key := cert.PublicKeyAlgorithm.String()
	var keyBits int
	switch key {
	case "RSA":
		keyBits = cert.PublicKey.(*rsa.PublicKey).N.BitLen()
		return "RSA", keyBits
	case "EC":
		keyBits = cert.PublicKey.(*ecdsa.PublicKey).Params().BitSize
		return "EC", keyBits
	}

	return "UNKOWN_KEY_TYPE", -1
}
