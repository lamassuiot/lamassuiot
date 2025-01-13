package helpers

import (
	"crypto/x509/pkix"
	"fmt"

	cmodels "github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
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

func PkixNameEqual(a, b pkix.Name) bool {
	if a.CommonName != b.CommonName {
		return false
	}

	if len(a.Country) != len(b.Country) || (len(a.Country) > 0 && a.Country[0] != b.Country[0]) {
		return false
	}

	if len(a.Locality) != len(b.Locality) || (len(a.Locality) > 0 && a.Locality[0] != b.Locality[0]) {
		return false
	}

	if len(a.Organization) != len(b.Organization) || (len(a.Organization) > 0 && a.Organization[0] != b.Organization[0]) {
		return false
	}

	if len(a.OrganizationalUnit) != len(b.OrganizationalUnit) || (len(a.OrganizationalUnit) > 0 && a.OrganizationalUnit[0] != b.OrganizationalUnit[0]) {
		return false
	}

	if len(a.Province) != len(b.Province) || (len(a.Province) > 0 && a.Province[0] != b.Province[0]) {
		return false
	}

	return true
}
