package mocks

import (
	"context"
	"crypto/x509"
	"errors"
	"time"

	"github.com/go-kit/kit/log"
	lamassuca "github.com/lamassuiot/lamassuiot/pkg/ca/client"
	"github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
	caDTO "github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
	clientUtils "github.com/lamassuiot/lamassuiot/pkg/utils/client"
)

type LamassuCaClientConfig struct {
	client clientUtils.BaseClient
	logger log.Logger
}

func NewLamassuCaClientMock(logger log.Logger) (lamassuca.LamassuCaClient, error) {

	return &LamassuCaClientConfig{
		client: nil,
		logger: logger,
	}, nil
}

func (c *LamassuCaClientConfig) GetCAs(ctx context.Context, caType caDTO.CAType) ([]caDTO.Cert, error) {

	var CAs []caDTO.Cert
	newCA := testCert()
	CAs = append(CAs, newCA)
	failDB := ctx.Value("DBShouldFail").(bool)

	if failDB {

		return CAs, errors.New("Error in client request")
	} else {
		return CAs, nil
	}
}

func (c *LamassuCaClientConfig) CreateCA(ctx context.Context, caType dto.CAType, caName string, privateKeyMetadata dto.PrivateKeyMetadata, subject dto.Subject, caTTL time.Duration, enrollerTTL time.Duration) (dto.Cert, error) {
	return dto.Cert{}, nil
}

func (c *LamassuCaClientConfig) ImportCA(ctx context.Context, caType dto.CAType, caName string, certificate x509.Certificate, privateKey dto.PrivateKey, enrollerTTL time.Duration) (dto.Cert, error) {

	return dto.Cert{}, nil
}

func (c *LamassuCaClientConfig) DeleteCA(ctx context.Context, caType dto.CAType, caName string) error {

	return nil
}
func (c *LamassuCaClientConfig) SignCertificateRequest(ctx context.Context, caType caDTO.CAType, caName string, csr *x509.CertificateRequest, signVerbatim bool) (*x509.Certificate, *x509.Certificate, error) {
	failDB := ctx.Value("SignCertificateRequestFail").(bool)

	if failDB {
		c := x509.Certificate{}
		c.Subject.CommonName = csr.Subject.CommonName
		return &c, nil, errors.New("Error revoking certificate")
	} else {
		c := x509.Certificate{}
		c.Subject.CommonName = csr.Subject.CommonName
		c.Issuer.CommonName = caName
		return &c, nil, nil
	}
}

func (c *LamassuCaClientConfig) RevokeCert(ctx context.Context, caType caDTO.CAType, caName string, serialNumberToRevoke string) error {
	failDB := ctx.Value("RevokeCertShouldFail").(bool)

	if failDB {
		return errors.New("Error revoking certificate")
	} else {

		return nil
	}
}

func (c *LamassuCaClientConfig) GetIssuedCerts(ctx context.Context, caType caDTO.CAType, caName string, queryParameters string) (caDTO.IssuedCertsResponse, error) {

	return caDTO.IssuedCertsResponse{}, nil
}

func (c *LamassuCaClientConfig) GetCert(ctx context.Context, caType caDTO.CAType, caName string, SerialNumber string) (caDTO.Cert, error) {
	failDB := ctx.Value("GetCertFail").(bool)

	if ctx.Value("DateFormatError") != nil {
		failDF := ctx.Value("DateFormatError").(bool)
		if failDF {
			return caDTO.Cert{}, errors.New("Error getting certificate")
		} else {
			c := testCert()
			c.ValidFrom = ""
			c.ValidTo = ""
			return c, nil
		}
	} else {
		if failDB {
			return caDTO.Cert{}, errors.New("Error getting certificate")
		} else {
			return testCert(), nil
		}
	}

}

func testCert() caDTO.Cert {

	serialNumber := "1E-6A-EC-C2-05-64-EF-65-66-7F-5B-AE-7B-B4-15-25-19-E8-2C-87"

	keyMetadata := caDTO.PrivateKeyMetadataWithStregth{
		KeyType:     "RSA",
		KeyBits:     4096,
		KeyStrength: "high",
	}

	subject := caDTO.Subject{
		CN: "CA",
		OU: "ZPD",
		O:  "IKL",
		L:  "Arrasate",
		ST: "Gipuzkoa",
		C:  "ES",
	}

	certContent := caDTO.CertContent{
		CerificateBase64: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZtVENDQTRHZ0F3SUJBZ0lVSG1yc3dnVms3MlZtZjF1dWU3UVZKUm5vTEljd0RRWUpLb1pJaHZjTkFRRUwKQlFBd1hERUxNQWtHQTFVRUJoTUNSVk14RVRBUEJnTlZCQWdNQ0VkcGNIVjZhMjloTVJFd0R3WURWUVFIREFoQgpjbkpoYzJGMFpURU1NQW9HQTFVRUNnd0RTVXRNTVF3d0NnWURWUVFMREFOYVVFUXhDekFKQmdOVkJBTU1Ba05CCk1CNFhEVEl5TURJeE5qRXhORGd4TTFvWERUSXpNREl4TmpFeE5EZ3hNMW93WERFTE1Ba0dBMVVFQmhNQ1JWTXgKRVRBUEJnTlZCQWdNQ0VkcGNIVjZhMjloTVJFd0R3WURWUVFIREFoQmNuSmhjMkYwWlRFTU1Bb0dBMVVFQ2d3RApTVXRNTVF3d0NnWURWUVFMREFOYVVFUXhDekFKQmdOVkJBTU1Ba05CTUlJQ0lqQU5CZ2txaGtpRzl3MEJBUUVGCkFBT0NBZzhBTUlJQ0NnS0NBZ0VBbWhONFVIdnRUcTVyelhXN01ibzltNTRicXRoeVlvdlNOODZmWkxFN0FqS3gKSVVpU0JCSVFUZkwyWVdqdXB5NFFBR0ZhU085WXk1Q1MvOVV1MWZTYTkrcFJ1QmVBZ1hVSTVzcXhlZEN6WEtScgpPT0R3L1I0dGkydVJUUEpzZWJ2K3l3MUswd3Z0R00yTXlLYTMyNFRMZnQ5UE05Nlc5VWsrOHlYc1dYQlo2Z1g4CnQ5cHJydkFrWkNRUlhDbTZ5amg1RWRIb2QxRy82TU95Y0RMVVN6RGhwcVpHaFVjTnl0RUxiOHA2ZGllNTRPOVoKWlB3TDl2QmpWemNROHo0WDBiWi9RbFJUcWhIQXJxUUxHaG02TTlTdkxUM0hLU1NoL1BpU2JhODk1V3h0OGJNMAo0Um9zYy96aDN3eVVSZVV1SFdQZm9uQWFGWjAxNFJCQ1Bud3Zub0dVeW8xRDIreWxncnhqRkJOQndzbm0rU1NPClVnN09JU05XaDRHK1RYa2JrK1RSajEvV0RGV2lDcC8wdmlacS95ZE02WWJNRHp2eWl0NWhsUnBxNXpYTzVFZi8KYlZmbVk0RXd2Ukx2RkVkNE1SelI2SWQrRjB4UWd1MFFWWmYwZHdGVU12V2Q2dUZOa3NSbDl2Z3hiNmZyQVFHbgp1VkVvTnVBN1VUZ1NCOVA5aXFKY2tBMFhacjQyaEcwYUw2b0FPdUxYZHU0azFkcm5ZMzRwdFhPRGNuRjBBMWl2ClV6SFhCNm9UNlRhSk5hQUlRVm5ETWJhWkRjcldGdmpVam9TNU45L2crQlRmVW42dWV1U3MzaTk5cHlZWTJ2Z24KVDFyV2xHUng2azQ5V2tBajQ3OG1wdFd6K01VeFJJVkl5bFlCNmxlMGUvMHlLR3FuZWd1R3Z4N0JjanhqTVhFQwpBd0VBQWFOVE1GRXdIUVlEVlIwT0JCWUVGQjNTNkE5NTQzT21oaTNhVFpYQVM2VjRiRjlKTUI4R0ExVWRJd1FZCk1CYUFGQjNTNkE5NTQzT21oaTNhVFpYQVM2VjRiRjlKTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3RFFZSktvWkkKaHZjTkFRRUxCUUFEZ2dJQkFGdHFRVEZUNGozcmUwanJrSjZBUDBrMk0raWhYall0MVk1c0ZvbWNaY2pFaWVKcApETDJDam04WEdnRWNHdkp6K01oSDY1T2hITHZIRU9tbjkvckcwWStsTzhhYmhTQ1pIZWVqYWRLNEFSSlhHSlQ3CkZPRVBDNjgrRVl5SG9wai8xUmRCSXhjMkN4WFFwOC9IYzA2bDVOUTBZS3ZmYW5vM0ZGSFZEN09YT2tQSTVNSWcKN1JDOWVNL2Z4NlVyaHNhVTNERzlMcVBxNEMzcFFmRnEvTHBublBnYjRsbmlRQVZ0ZXRoWWhNSHFDUHdMMVJvQQoxTmdUZmJrWjBQaDl6N2cySUF4MW9SOXo5dWk0WWRWOVpycjhQTDBPaG4zM3BPbFJrZDNUcWJiY3FWcHBEL282CmFYZlJVU2taQWhoMXg4MlpzN2U2b2x4ekNTc3p0KzhUOTRtU0I5OWRoSDJiVnh4RWpPb3cvSklwNnlMT2JnUGcKdjZaRzROMEVaU2JlSGRzZ2ovbTd6RHg5Tlk2WGkrTUpidGlZdkRrdWpnRjdPanpVZkF3TUFaRzdOR0YraDNMWgpKb2EzQUg0ZDQ2UjFRVXRLQTdmUEpVb0pTb0xTVDZSOW9PR3dacUEzK1p6dDd4VFNoZkc2VDY0OWYxZ2c3OFhoCmRtM3hRYjZERUQvYk1iY3hGZUlvUW0yTklBS3VyUkMrV0hCMXFpZWlEdnZNd21IdjZGNHlvVWpNWEsyQVdWZysKWEJmb01KejZTYWZaOFlBWEhyVWdCdG8rVi95WTNaZzErOWdva0ZIOUkySHRFK1dOeUZjdUc3NEFoWlNMUHdiVgpwaE1FQUhHeTZVZWZaWlVpRTJ4SHFZRElDbVlWUlBUNGdrWlNqTXFKRDZ6ZExWTUNLcG81RnFXbEdvZEQKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQ==",
		PublicKeyBase64:  "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFNWkxcWZ5WVNsS2lrd0g4RmZIb0FsVVhOOEZRNwpoTU4wRFpOTy9XN2JITjg1UWlnT1l5VDVtY1gyV2wybUk1RC9MUE9QSndJeDdWWXJsWVNQTE5uZ3Z3PT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==",
	}

	cert := caDTO.Cert{
		Status:       "issued",
		SerialNumber: serialNumber,
		Name:         "CA",
		KeyMetadata:  keyMetadata,
		Subject:      subject,
		CertContent:  certContent,
		ValidFrom:    "2021-02-16 16:42:31.3773933 +0000 UTC",
		ValidTo:      "2022-01-01 16:42:31.3773933 +0000 UTC",
	}
	return cert
}
