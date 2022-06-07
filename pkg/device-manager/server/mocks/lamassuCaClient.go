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
	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"
)

type LamassuCaClientConfig struct {
	client clientUtils.BaseClient
	logger log.Logger
}

var cert = CreateTestCA("1E-6A-EC-C2-05-64-EF-65-66-7F-5B-AE-7B-B4-15-25-19-E8-2C-87", false)

func NewLamassuCaClientMock(logger log.Logger) (lamassuca.LamassuCaClient, error) {

	return &LamassuCaClientConfig{
		client: nil,
		logger: logger,
	}, nil
}

func (c *LamassuCaClientConfig) GetCAs(ctx context.Context, caType caDTO.CAType, queryparameters filters.QueryParameters) (caDTO.GetCasResponse, error) {
	var CAs caDTO.GetCasResponse
	var newCA caDTO.Cert
	if queryparameters.Pagination.Offset != 0 {
		return caDTO.GetCasResponse{}, nil
	}
	if caType == caDTO.DmsEnroller {
		newCA = CreateTestCA("", true)

	} else {
		newCA = CreateTestCA("", false)

	}
	CAs.CAs = append(CAs.CAs, newCA)
	if ctx.Value("DBShouldFail") != nil {
		failDB := ctx.Value("DBShouldFail").(bool)

		if failDB {
			return CAs, errors.New("Error in client request")
		} else {
			return CAs, nil
		}
	} else {
		return CAs, nil
	}

}

func (c *LamassuCaClientConfig) CreateCA(ctx context.Context, caType dto.CAType, caName string, privateKeyMetadata dto.PrivateKeyMetadata, subject dto.Subject, caTTL time.Duration, enrollerTTL time.Duration) (dto.Cert, error) {
	newCA := CreateTestCA("", false)
	return newCA, nil
}

func (c *LamassuCaClientConfig) ImportCA(ctx context.Context, caType dto.CAType, caName string, certificate x509.Certificate, privateKey dto.PrivateKey, enrollerTTL time.Duration) (dto.Cert, error) {

	return dto.Cert{}, nil
}

func (c *LamassuCaClientConfig) DeleteCA(ctx context.Context, caType dto.CAType, caName string) error {

	return nil
}
func (c *LamassuCaClientConfig) SignCertificateRequest(ctx context.Context, caType caDTO.CAType, caName string, csr *x509.CertificateRequest, signVerbatim bool, cn string) (*x509.Certificate, *x509.Certificate, error) {
	cert := x509.Certificate{}
	cert.Subject.CommonName = csr.Subject.CommonName
	if ctx.Value("DBShouldFail") != nil {
		failDB := ctx.Value("SignCertificateRequestFail").(bool)

		if failDB {

			return &cert, nil, errors.New("Error revoking certificate")
		} else {
			c := x509.Certificate{}
			c.Subject.CommonName = csr.Subject.CommonName
			c.Issuer.CommonName = caName
			return &c, nil, nil
		}
	} else {
		return &cert, nil, nil
	}
}

func (c *LamassuCaClientConfig) RevokeCert(ctx context.Context, caType caDTO.CAType, caName string, serialNumberToRevoke string) error {
	if ctx.Value("DBShouldFail") != nil {
		if ctx.Value("RevokeCertShouldFail") != nil {
			failDB := ctx.Value("RevokeCertShouldFail").(bool)
			if failDB {
				return errors.New("Error revoking certificate")
			} else {
				return nil
			}
		} else {
			return nil
		}
	} else {
		return nil
	}
}

func (c *LamassuCaClientConfig) GetIssuedCerts(ctx context.Context, caType caDTO.CAType, caName string, queryParameters filters.QueryParameters) (caDTO.IssuedCertsResponse, error) {

	return caDTO.IssuedCertsResponse{}, nil
}

func (c *LamassuCaClientConfig) GetCert(ctx context.Context, caType caDTO.CAType, caName string, SerialNumber string) (caDTO.Cert, error) {
	if cert.SerialNumber != SerialNumber {
		return caDTO.Cert{}, errors.New("Error getting certificate")
	} else {
		if ctx.Value("DBGetCert") != nil {

			failDB := ctx.Value("DBGetCert").(bool)
			if failDB {
				return caDTO.Cert{}, errors.New("Error getting certificate")
			}

		}
		if caType == caDTO.DmsEnroller {
			return CreateTestCA(SerialNumber, true), nil
		} else {
			return CreateTestCA(SerialNumber, false), nil

		}

	}
}

func CreateTestCA(SerialNumber string, dmsenroller bool) caDTO.Cert {

	if dmsenroller {
		keyMetadata := caDTO.PrivateKeyMetadataWithStregth{
			KeyType:     "RSA",
			KeyBits:     4096,
			KeyStrength: "high",
		}

		subject := caDTO.Subject{
			CommonName:       "Lamassu DMS Enroller",
			OrganizationUnit: "Lamassu PKI",
			Organization:     "",
			Locality:         "",
			State:            "",
			Country:          "",
		}

		certContent := caDTO.CertContent{
			CerificateBase64: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZYVENDQTBXZ0F3SUJBZ0lVUkNlMlBsdG5vdmhCaXQ5UzA0V2RkVVp3VnVrd0RRWUpLb1pJaHZjTkFRRUwKQlFBd05URVVNQklHQTFVRUNoTUxUR0Z0WVhOemRTQlFTMGt4SFRBYkJnTlZCQU1URkV4aGJXRnpjM1VnUkUxVApJRVZ1Y205c2JHVnlNQ0FYRFRJeU1ETXhNREV3TURnME5sb1lEekl3TlRJd016QXlNVEF3T1RFMFdqQTFNUlF3CkVnWURWUVFLRXd0TVlXMWhjM04xSUZCTFNURWRNQnNHQTFVRUF4TVVUR0Z0WVhOemRTQkVUVk1nUlc1eWIyeHMKWlhJd2dnSWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUNEd0F3Z2dJS0FvSUNBUURUZFJMNWRocGVXWjZqUDZlKwpaWmdMQ1dtRTE3VitQTFlsOFJ1bE0rRU00UnF5dTJXTXRBOVgwUGJySzQwekVmMlUrbkdiaEpTemNkbHU2NU1nCkJaR25EZFhjWVZqajRCcUEyR0JZT0hxNnFncmZlUTVtK2hteG9VdXA1dk9tYU9UUjZ3RllVS1d1a2NkTnh3cVYKR29ybDkvUm1zcEpvN2RJWWNzQ1VBaG9DR1RVL3BYRkxYcjhxS0Q2TmJ1cHpCcVNkSERFTmF5MjBSamVkUUZjdwpOdnMzVHNTRkJId2tRcnJQMkg0TU1CMHhTSzBOY0NyOWtyd2RhZE5QOGJYMlVpcldMdldHeWE5dlVxSWFRUldUCmFSVzI2a1cveDFrTW9UdkJHZWxiYTdtdzZwZi9kNHNZK1lENG82M2gxTXJEM0lraGlmR0RCZWVyQ1RjRnYyVkkKK1VYaTFIZmxhT2RUSU9oUVZZWk9laE5GSXpVZmhvek9LZXA2Y2dCRGpPR01lOFg2UTlCdjV0MldWQUcyUkNYSgpFd3NyTUZWeE1yTVhYUXBzbFVQZVNQbmI3WDNlRVl4MHVhMHNPZDJ3NHNEeGVZYW00eWhyNWpWbEg3T25uRjZ0CmJURHZXVTlnVVBaeTJSbEJSTFBtYmNIQVFEZXc0dyttYmZHeVRmb3NnSVpFdDFIRjVlOGcwN25sQU92cklIUEYKdFJKZVpWNEdadEwveXZHcjhXMzRZZXRoUDRxd0xjamZrQ2FLTWN2ZytOVllUUmtvaHdZMENnTzRBbHlVT1VUbwpZY3pMZUJWQVoxdUlpMTdPNXFxMU1ZNnlZVEJmQkJuSzI1QWdIWTdkM2RRczR2djhvdlN2akkwY2RLMGtPc084CnI5V0UxaTdQNkVUZmVBeUZtZDlFZ0gxTkl3SURBUUFCbzJNd1lUQU9CZ05WSFE4QkFmOEVCQU1DQVFZd0R3WUQKVlIwVEFRSC9CQVV3QXdFQi96QWRCZ05WSFE0RUZnUVVGSEIvWmpwME5VSThidWk3QUIxdmQ0VkIvRWd3SHdZRApWUjBqQkJnd0ZvQVVGSEIvWmpwME5VSThidWk3QUIxdmQ0VkIvRWd3RFFZSktvWklodmNOQVFFTEJRQURnZ0lCCkFFRUxGejk0Z3Z4VFJHU3J2OE8zbHNSZW9RZ1FxckZiVnQ1V0NBaFVWSEVpdGZyQno3VklnWWJKamRydUZBVncKNUM1SUlYQnJhT2d2R1NGV2RVMVpUYXR5YkEzZ0ZiV1poNURVSE9QdUkxY0UwZmJIV2RzYmZYZEY5WmhLcEFJdApnNEFsNTFUOVVORUpGaDN1YnAydGJZVmUzVGdOWVlpV1BpNlo0RWl1Yk96b1pyUmtjbzhFR0NkdHVhOVVObFRLClduTVV6Z3MrVis0bG41bmNURVdTZ2JXNy85Nkk2bmowb3ArRElDNHlmWTVWd3ZtaXZtRmZYUnd6Z1JNVnNLb1IKMW9XMmw3SjFmWElScjFxVXhmdUZHbDkxaWRlTmNFY3c0dG14MEtlcWk1azcrZkVmKzExcVZYSzdBQkpuZnpVTgp3UlN1bklGVXc2NTd3Q01KMkt1allwT0V2NTVmZHNUeDZJajllNldwM3JNUnpHMEJrM2xud1ZHeEkwM09DbHluCjFZcHd4aEd3eHdwTVY3aVh5dm5SQUJ5UjVsNWkvTTQvQ1JHWDFDTGx4Nnh5YzRpbXF3Z3ZOQTk1TURBV3RvZGQKY2tUZnUwclArUFVjaWZaN0R2SnFmY2RRLzFWbGNaRWtUeFNQU2xTWnNRUXRBNGxyTVJxaXJ1YzlMMHgyUytxMQpFK1IxeVZLT3pFWmZGWnM0YitWZ2ZQTFhReGY5Q25QWmoyS2RuOG9IbkJMR2tLUFJhUWx2eEpYbTA3cTdCUFBhCjN0Zm13c2pLYjNnQUwwRzAyVEZ3Mk5IVkwzVmhaV1VObTlLSUdKZXkzeTlDNXBZbjJPMGdnUHZGcmVNb1F3K2MKVFcxYTNFYW9oMVZQMTVTM3hUZVRtUUpvaUNVWUFhTk5BYU83T2pQaHB1UG4KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQ==",
			PublicKeyBase64:  "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQ0lqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FnOEFNSUlDQ2dLQ0FnRUEwM1VTK1hZYVhsbWVveitudm1XWQpDd2xwaE5lMWZqeTJKZkVicFRQaERPRWFzcnRsakxRUFY5RDI2eXVOTXhIOWxQcHhtNFNVczNIWmJ1dVRJQVdSCnB3M1YzR0ZZNCtBYWdOaGdXRGg2dXFvSzMza09adm9ac2FGTHFlYnpwbWprMGVzQldGQ2xycEhIVGNjS2xScUsKNWZmMFpyS1NhTzNTR0hMQWxBSWFBaGsxUDZWeFMxNi9LaWcralc3cWN3YWtuUnd4RFdzdHRFWTNuVUJYTURiNwpOMDdFaFFSOEpFSzZ6OWgrRERBZE1VaXREWEFxL1pLOEhXblRUL0cxOWxJcTFpNzFoc212YjFLaUdrRVZrMmtWCnR1cEZ2OGRaREtFN3dSbnBXMnU1c09xWC8zZUxHUG1BK0tPdDRkVEt3OXlKSVlueGd3WG5xd2szQmI5bFNQbEYKNHRSMzVXam5VeURvVUZXR1Rub1RSU00xSDRhTXppbnFlbklBUTR6aGpIdkYra1BRYitiZGxsUUJ0a1FseVJNTApLekJWY1RLekYxMEtiSlZEM2tqNTIrMTkzaEdNZExtdExEbmRzT0xBOFhtR3B1TW9hK1kxWlIrenA1eGVyVzB3CjcxbFBZRkQyY3RrWlFVU3o1bTNCd0VBM3NPTVBwbTN4c2szNkxJQ0dSTGRSeGVYdklOTzU1UURyNnlCenhiVVMKWG1WZUJtYlMvOHJ4cS9GdCtHSHJZVCtLc0MzSTM1QW1pakhMNFBqVldFMFpLSWNHTkFvRHVBSmNsRGxFNkdITQp5M2dWUUdkYmlJdGV6dWFxdFRHT3NtRXdYd1FaeXR1UUlCMk8zZDNVTE9MNy9LTDByNHlOSEhTdEpEckR2Sy9WCmhOWXV6K2hFMzNnTWhabmZSSUI5VFNNQ0F3RUFBUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=",
		}

		cert := caDTO.Cert{
			Status:       "issued",
			SerialNumber: "44-27-b6-3e-5b-67-a2-f8-41-8a-df-52-d3-85-9d-75-46-70-56-e9",
			Name:         "Lamassu-DMS-Enroller",
			KeyMetadata:  keyMetadata,
			Subject:      subject,
			CertContent:  certContent,
			ValidFrom:    "2022-03-10 10:08:46 +0000 UTC",
			ValidTo:      "2052-03-02 10:09:14 +0000 UTC",
		}
		return cert
	} else {
		serialNumber := SerialNumber

		keyMetadata := caDTO.PrivateKeyMetadataWithStregth{
			KeyType:     "RSA",
			KeyBits:     4096,
			KeyStrength: "high",
		}

		subject := caDTO.Subject{
			CommonName:       "CA",
			OrganizationUnit: "ZPD",
			Organization:     "IKL",
			Locality:         "Arrasate",
			State:            "Gipuzkoa",
			Country:          "ES",
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
		//cert.CertContent.CerificateBase64 = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUU0akNDQXNxZ0F3SUJBZ0lVWWpGTUUrczhqZE9JTkF0Rkk1UHNMN0x5NDFVd0RRWUpLb1pJaHZjTkFRRUwKQlFBd05URVVNQklHQTFVRUNoTUxUR0Z0WVhOemRTQlFTMGt4SFRBYkJnTlZCQU1URkV4aGJXRnpjM1VnUkUxVApJRVZ1Y205c2JHVnlNQjRYRFRJeU1EVXdOVEV5TXpBME5Wb1hEVFF5TURRek1ERXlNekV4TlZvd1RURUpNQWNHCkExVUVCaE1BTVFrd0J3WURWUVFJRXdBeENUQUhCZ05WQkFjVEFERUpNQWNHQTFVRUNoTUFNUWt3QndZRFZRUUwKRXdBeEZEQVNCZ05WQkFNVEMwUmxabUYxYkhRdFJFMVRNSUlCb2pBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVk4QQpNSUlCaWdLQ0FZRUEyMWpSU2VrVXNFM2s5TWdSbXV6YVQyNHpLeWZRMDA3QUpZQS82MktjQmtZdXlVWURNakdKCmhFQ3lBbGh2YWZjTVBiYUNwYTM3MmVlSDFpY3dQbzhqOHkxTENLMjFXM1loUDRNR0d2d2poWCtJLzQ4YkdkTTgKbFJEWXFsaDBYK2Y2TkZXd1kvTXdHQ1hBRU1nRE5kVWFNZkhjWXNYYko3OUtUeUwwbEw1NWNWWGs3ZGh6cGhDSApVTDFiZm4zVXM5aDdtcW5Na2ZrdFB1K1lGT0FkL2F5cytTQVBGMGNDOFU0SURwSE1hVjcyMlpHSkl2amhXRVBFClVZd3dmQmVXODdjZlZTb3AwdHpQejhkZW01KzA3UmVlbk1DanRRMGxZcmhLbi9KeVNTQVpoMm5Gb0ttdXZKc2oKQk9jL0hlaHVGME5yTHlHRFU5M01tNlY4Ny9PL3VYOG9Oc1BSZWM5UzRWTlFXUG9pVlViSTVwSGw4dVZzRG1tcgp2L2prQ3E1ZUJMZTVzMHRhbjdIbDNobjVXQU5RMk51azRVeTF0SlZENzl0Z1g4ODExbWp4eEo1b1dBQWxjVUNDCi9GMmthRmdSSllEQVdSbm9yZW4ybGdKcVdTU3VGL1liVXkybGZWMHZvV1AvVlV5RE1nS01HdGZjSFhiNG8yOWMKUFYxMXYvT3FOaXQvQWdNQkFBR2pVakJRTUE0R0ExVWREd0VCL3dRRUF3SURxREFkQmdOVkhRNEVGZ1FVSGhYMwpzSHFINHpnZnFmM1RLWnAvRDhxd2NJQXdId1lEVlIwakJCZ3dGb0FVRkhCL1pqcDBOVUk4YnVpN0FCMXZkNFZCCi9FZ3dEUVlKS29aSWh2Y05BUUVMQlFBRGdnSUJBRlpHcFpia3Rmbk1FR3NEYUo2ZWtRL2ZkekQ4aHBnTE5BS2EKSHc4aHMzS0F2Q3QrMUM3bzJyR2JKcXg3K1UvYzlJSjR6V1BEOEtZQS9id1lyZ2RLWXp5MUk3dDhjSmViZUdTNQpiYy9xMEgwRVdrbHphTEM5RUlrRlc3bnAyRHhmd3ZOb083cjllN1puMDc4WWd6b2xjV3MwbGFpT3FBbmtRcUkyClhnd3dudU9zQ28waFYwQ3pYUlJlTkt6bVdPVVNVVHNRRS9pMDNJL0pJdkRPZm9VNUo3TXFpNVNvajlmTllzSlEKVHlKbGhlQlZZZmRIeXNSTVFzVzV6K0NNbVRwTlUxRnF1VGVER2hMbjdEOWNaVDJuRk9jVGIvczBla2FHci9zeQpGSDlzeG8rWUNMczlXM3NNUnNLS3F0UW90aDlWdzA5TUVJWCtaTWUxVUxWbXM4RHh0ZEg2Y0ZhMkZNVzNYc1NoCnRxdlc1N3UxNUd0Yk5aTEFjOEZOaG8xLzZuck5NdVdJNW4ycVFVNTZDN09MR0UraXlZVzhCS3hOeWJMWUdReVYKcy9EQWN0S0FLVFlLaGcvKzIwb2lwZlhncVZkN0tBTldkN3hQVkZoeFJFM1Vsb1pFbWNISm83TXJrclBFbG9mbworNVBneitMVEtQZ1loa2JLaWxtNENRM2RGVXNQRW9jTWVXWk5hQmdDNk1CbmRrNkJOWFRoMDVuVXVMcWJlQ3BTCmlwMHF0aE5nNUgvS0VaQ0tucTk4dDkxaHV2UW0wRUFzY1hQZk1BSHJVRXgwK1NNUVZZMUhzTWF1K1BKUzZUUVoKU0ZvbkpGbTZuWVZEbjNnby9adTlWRmFJSkZrZXVLQnBTTzQzR3Y2c2M3cGxNSmZ1UFY0TFJpNTRFRWR6RmoxRQpiajFQMExMbQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t"

		return cert
	}
}
