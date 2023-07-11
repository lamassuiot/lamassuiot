package helpers

import (
	"crypto/x509/pkix"

	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
)

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
