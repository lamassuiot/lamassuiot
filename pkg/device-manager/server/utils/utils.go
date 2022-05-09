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
)

type Utils interface {
	VerifyPeerCertificate(ctx context.Context, cert *x509.Certificate, enroll bool, certCA *x509.Certificate) (string, error)
	GetCertsCAType(ctx context.Context, enroll bool) ([]*x509.Certificate, []caDTO.Cert, error)
	GenerateCSR(csr *x509.CertificateRequest, key interface{}) (*x509.CertificateRequest, error)
	InsertNth(s string, n int) string
	ToHexInt(n *big.Int) string
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
	for _, v := range certs {
		data, _ := base64.StdEncoding.DecodeString(v.CertContent.CerificateBase64)
		block, _ := pem.Decode([]byte(data))
		if bytes.Equal(block.Bytes, b.Bytes) {
			aps = v.Name

		}
	}
	return aps, err
}
func (u *UtilsService) GetCertsCAType(ctx context.Context, enroll bool) ([]*x509.Certificate, []caDTO.Cert, error) {
	var certs []caDTO.Cert
	if !enroll {
		caType, err := caDTO.ParseCAType("pki")
		certs, err = u.lamassuCaClient.GetCAs(ctx, caType)
		if err != nil {
			level.Error(u.logger).Log("err", err, "msg", "Error in client request")
			return nil, certs, err
		}
	} else {
		caType, err := caDTO.ParseCAType("dmsenroller")
		certs, err = u.lamassuCaClient.GetCAs(ctx, caType)
		if err != nil {
			level.Error(u.logger).Log("err", err, "msg", "Error in client request")
			return nil, certs, err
		}
	}
	CAsCertificates := []*x509.Certificate{}
	for _, v := range certs {
		data, _ := base64.StdEncoding.DecodeString(v.CertContent.CerificateBase64)
		block, _ := pem.Decode([]byte(data))
		certificate, _ := x509.ParseCertificate(block.Bytes)
		CAsCertificates = append(CAsCertificates, certificate)
	}
	return CAsCertificates, certs, nil
}

func (u *UtilsService) GenerateCSR(csr *x509.CertificateRequest, key interface{}) (*x509.CertificateRequest, error) {

	subj := pkix.Name{
		Country:            []string{csr.Subject.Country[0]},
		Province:           []string{csr.Subject.Province[0]},
		Organization:       []string{csr.Subject.Organization[0]},
		OrganizationalUnit: []string{csr.Subject.OrganizationalUnit[0]},
		Locality:           []string{csr.Subject.Locality[0]},
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
