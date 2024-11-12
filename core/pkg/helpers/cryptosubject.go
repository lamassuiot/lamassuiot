package helpers

import (
	"crypto/x509/pkix"
	"fmt"

	cmodels "github.com/lamassuiot/lamassuiot/v3/core/pkg/models"
)

func SubjectToPkixName(subj cmodels.Subject) pkix.Name {
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

func PkixNameToSubject(pkixName pkix.Name) cmodels.Subject {
	subject := cmodels.Subject{
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

func PkixNameToString(subject pkix.Name) string {
	return fmt.Sprintf("C=%v/ST=%v/L=%v/O=%v/OU=%v/CN=%s", subject.Country, subject.Province, subject.Locality, subject.Organization, subject.OrganizationalUnit, subject.CommonName)
}
