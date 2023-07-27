package services

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"

	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/resources"
)

type ListInput[E any] struct {
	QueryParameters *resources.QueryParameters
	ExhaustiveRun   bool //wether to iter all elems
	ApplyFunc       func(cert *E)
}

func insertNth(s string, n int, sep rune) string {
	if len(s)%2 != 0 {
		s = "0" + s
	}
	var buffer bytes.Buffer
	var n_1 = n - 1
	var l_1 = len(s) - 1
	for i, rune := range s {
		buffer.WriteRune(rune)
		if i%n == n_1 && i != l_1 {
			buffer.WriteRune(sep)
		}
	}
	return buffer.String()
}

func toHexInt(n *big.Int) string {
	return fmt.Sprintf("%x", n) // or %X or upper case
}

func SerialNumberToString(n *big.Int) string {
	return insertNth(toHexInt(n), 2, '-')
}

func SubjectToPkixName(subj models.Subject) pkix.Name {
	subjPkix := pkix.Name{}

	if subj.CommonName != "" {
		subjPkix.CommonName = subj.CommonName
	}

	if subj.Country != "" {
		subjPkix.Country = []string{
			subj.Country,
		}
	}

	if subj.Locality != "" {
		subjPkix.Locality = []string{
			subj.Locality,
		}
	}

	if subj.Organization != "" {
		subjPkix.Organization = []string{
			subj.Organization,
		}
	}

	if subj.OrganizationUnit != "" {
		subjPkix.OrganizationalUnit = []string{
			subj.OrganizationUnit,
		}
	}

	if subj.State != "" {
		subjPkix.Province = []string{
			subj.State,
		}
	}

	return subjPkix
}

func PkixNameToSubject(pkixName pkix.Name) models.Subject {
	subject := models.Subject{
		CommonName: pkixName.CommonName,
	}

	if len(pkixName.Country) > 0 {
		subject.Country = pkixName.Country[0]
	}
	if len(pkixName.Organization) > 0 {
		subject.Organization = pkixName.Organization[0]
	}
	if len(pkixName.OrganizationalUnit) > 0 {
		subject.OrganizationUnit = pkixName.OrganizationalUnit[0]
	}
	if len(pkixName.Locality) > 0 {
		subject.Locality = pkixName.Locality[0]
	}
	if len(pkixName.Province) > 0 {
		subject.State = pkixName.Province[0]
	}

	return subject
}

func ReadCertificateFromFile(filePath string) (*x509.Certificate, error) {
	if filePath == "" {
		return nil, fmt.Errorf("cannot open empty filepath")
	}

	certFileBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	certDERBlock, _ := pem.Decode(certFileBytes)

	return x509.ParseCertificate(certDERBlock.Bytes)
}
