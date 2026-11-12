package x509engines

import (
	"crypto/x509"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestAddDistributionPointsUsesTheIssuerCAID(t *testing.T) {
	engine := NewX509Engine(logrus.NewEntry(logrus.New()), []string{"va1.example.com", "va2.example.com"}, nil)

	for name, tc := range map[string]struct{ id, want string }{
		"uuid":                 {"018f2d6e-7b3a-7c1e-9a4b-0123456789ab", "018f2d6e-7b3a-7c1e-9a4b-0123456789ab"},
		"id of an older CA":    {"factory.root-1_a", "factory.root-1_a"},
		"unsafe id is escaped": {"a b/c", "a%20b%2Fc"},
	} {
		t.Run(name, func(t *testing.T) {
			template := &x509.Certificate{}
			engine.addDistributionPoints(template, tc.id)
			require.Equal(t, []string{"http://va1.example.com/crl/" + tc.want, "http://va2.example.com/crl/" + tc.want}, template.CRLDistributionPoints)
			require.Equal(t, []string{"http://va1.example.com/ocsp", "http://va2.example.com/ocsp"}, template.OCSPServer)
		})
	}
}
