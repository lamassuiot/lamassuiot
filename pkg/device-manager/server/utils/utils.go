package utils

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	lamassuca "github.com/lamassuiot/lamassuiot/pkg/ca/client"
	caDTO "github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"
)

type Utils interface {
	VerifyPeerCertificate(ctx context.Context, cert *x509.Certificate, enroll bool, certCA *x509.Certificate) (string, error)
	GetCertsCAType(ctx context.Context, enroll bool) ([]*x509.Certificate, caDTO.GetCasResponse, error)
	GenerateCSR(csr *x509.CertificateRequest, key interface{}) (*x509.CertificateRequest, error)
	CheckIfNull(field []string) string
}
type UtilsService struct {
	logger          log.Logger
	lamassuCaClient lamassuca.LamassuCaClient
}

func NewUtils(lamassuCaClient *lamassuca.LamassuCaClient, logger log.Logger) Utils {
	return &UtilsService{
		lamassuCaClient: *lamassuCaClient,
		logger:          logger,
	}
}

func (u *UtilsService) VerifyPeerCertificate(ctx context.Context, cert *x509.Certificate, enroll bool, certCA *x509.Certificate) (string, error) {
	if certCA != nil {
		clientCAs := x509.NewCertPool()
		clientCAs.AddCert(certCA)

		opts := x509.VerifyOptions{
			Roots:     clientCAs,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		_, err := cert.Verify(opts)
		if err != nil {
			level.Error(u.logger).Log("err", err, "msg", "Error in certificate verification")
			return "", err
		}
		return "", err
	}
	CAsCertificates, certs, err := u.GetCertsCAType(ctx, enroll)
	if err != nil {
		level.Error(u.logger).Log("err", err, "msg", "Error in GetCAs request")
		return "", err
	}
	clientCAs := x509.NewCertPool()
	for _, certificate := range CAsCertificates {
		clientCAs.AddCert(certificate)
	}

	opts := x509.VerifyOptions{
		Roots:     clientCAs,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	candidateCa, err := cert.Verify(opts)
	if err != nil {
		level.Error(u.logger).Log("err", err, "msg", "Error in certificate verification")
		return "", err
	}
	CA := candidateCa[0][1]
	b := pem.Block{Type: "CERTIFICATE", Bytes: CA.Raw}
	var aps string
	for _, v := range certs.CAs {
		data, _ := base64.StdEncoding.DecodeString(v.CertContent.CerificateBase64)
		block, _ := pem.Decode([]byte(data))
		if bytes.Equal(block.Bytes, b.Bytes) {
			aps = v.Name

		}
	}
	return aps, err
}
func (u *UtilsService) GetCertsCAType(ctx context.Context, enroll bool) ([]*x509.Certificate, caDTO.GetCasResponse, error) {
	var certs caDTO.GetCasResponse
	if !enroll {
		caType, _ := caDTO.ParseCAType("pki")
		limit := 50
		i := 0
		for {
			cas, err := u.lamassuCaClient.GetCAs(ctx, caType, filters.QueryParameters{Pagination: filters.PaginationOptions{Limit: limit, Offset: i * limit}})
			if err != nil {
				level.Error(u.logger).Log("err", err, "msg", "Error in client request")
				return nil, certs, err
			}
			if len(cas.CAs) == 0 {
				break
			}
			certs.CAs = append(certs.CAs, cas.CAs...)
			i++
		}
	} else {
		caType, err := caDTO.ParseCAType("dmsenroller")
		certs, err = u.lamassuCaClient.GetCAs(ctx, caType, filters.QueryParameters{})
		if err != nil {
			level.Error(u.logger).Log("err", err, "msg", "Error in client request")
			return nil, certs, err
		}
	}
	CAsCertificates := []*x509.Certificate{}
	for _, v := range certs.CAs {
		data, _ := base64.StdEncoding.DecodeString(v.CertContent.CerificateBase64)
		block, _ := pem.Decode([]byte(data))
		certificate, _ := x509.ParseCertificate(block.Bytes)
		CAsCertificates = append(CAsCertificates, certificate)
	}
	return CAsCertificates, certs, nil
}

func (u *UtilsService) GenerateCSR(csr *x509.CertificateRequest, key interface{}) (*x509.CertificateRequest, error) {

	subj := pkix.Name{
		Country:            []string{u.CheckIfNull(csr.Subject.Country)},
		Province:           []string{u.CheckIfNull(csr.Subject.Country)},
		Organization:       []string{u.CheckIfNull(csr.Subject.Country)},
		OrganizationalUnit: []string{u.CheckIfNull(csr.Subject.Country)},
		Locality:           []string{u.CheckIfNull(csr.Subject.Country)},
		CommonName:         csr.Subject.CommonName,
	}
	rawSubject := subj.ToRDNSequence()
	asn1Subj, _ := asn1.Marshal(rawSubject)
	template := x509.CertificateRequest{
		RawSubject: asn1Subj,
		//EmailAddresses:     []string{emailAddress},
		SignatureAlgorithm: x509.ECDSAWithSHA512,
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %v", err)
	}

	csrNew, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate request: %v", err)
	}
	return csrNew, nil
}

func (u *UtilsService) ToHexInt(n *big.Int) string {
	return fmt.Sprintf("%x", n) // or %X or upper case
}

func (u *UtilsService) InsertNth(s string, n int) string {
	if len(s)%2 != 0 {
		s = "0" + s
	}
	var buffer bytes.Buffer
	var n_1 = n - 1
	var l_1 = len(s) - 1
	for i, rune := range s {
		buffer.WriteRune(rune)
		if i%n == n_1 && i != l_1 {
			buffer.WriteRune('-')
		}
	}
	return buffer.String()
}

func (u *UtilsService) CheckIfNull(field []string) string {
	var result = ""
	if field != nil {
		result = field[0]
	}
	return result
}
