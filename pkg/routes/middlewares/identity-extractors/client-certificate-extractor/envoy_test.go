package clientcertificateextractor

import (
	"net/http"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestEnvoyCertExtraction(t *testing.T) {
	headers := http.Header{}
	headers.Set("x-forwarded-client-cert", `Hash=9def1c1c6d6a7eb670aaf141c126ddb001a63a9c9203cb9e3bc7ca4b746c3d60;Chain="-----BEGIN%20CERTIFICATE-----%0AMIIDdTCCAxygAwIBAgIQX0L1bVPmFg5lLX1OuqlA0jAKBggqhkjOPQQDAjBnMQsw%0ACQYDVQQGEwJFUzERMA8GA1UECBMIR2lwdXprb2ExEDAOBgNVBAcTB0JlYXNhaW4x%0AEjAQBgNVBAoTCUdIIENyYW5lczEfMB0GA1UEAxMWR0ggQ29yZWJveCBJZGVudGl0%0AeSBDQTAeFw0yNDA3MTcxMDUwMDNaFw0yNjA3MTUxMDUwMDNaMDUxCzAJBgNVBAYT%0AAkVTMRIwEAYDVQQKEwlHSCBDcmFuZXMxEjAQBgNVBAMTCUNvcmVib3gtMTCCASIw%0ADQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKmEIfcVbkcwH0%2Bij9yCapYoWfzK%0A%2FUBIlYtaLMRqeFPT84ajjDcGrqcLvbJFifjyPzWnN4pl4enpdygHPaKVQC5ryWKS%0ACbGwlbDhgDfv%2B2eah1J6mp%2Bk9Hnll2AyrpIkQ2nSAvFLFSwwU7l3yccJqfozHPwP%0A%2FCDpupljivM3kk1mPcZn5IkzeIQBxDcGP%2FV2cTjSxx6viClMWXbQs48ub1WDp%2Bu6%0AaB8fyTOSlPqSTartP0QMnyHmPOIASm6zrQ36aWRrMuYOaIokwGcLogluMzW8L8nz%0AwJo9qi6%2FI5mDCHOz7K3a8ybuQmtjATVjz1cCNxyLT76UKAvBg94j6sBb51UCAwEA%0AAaOCAQ8wggELMA4GA1UdDwEB%2FwQEAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAgYI%0AKwYBBQUHAwEwLwYDVR0jBCgwJoAkZDEwM2YzODQtNDc0Ny00NWFhLTllYzEtNTE5%0AMTM4NTY0ZjMyMEcGCCsGAQUFBwEBBDswOTA3BggrBgEFBQcwAYYraHR0cHM6Ly9s%0AYW1zc3UtZGV2LmdoY3JhbmVzLmNvbS9hcGkvdmEvb2NzcDBgBgNVHR8EWTBXMFWg%0AU6BRhk9odHRwczovL2xhbXNzdS1kZXYuZ2hjcmFuZXMuY29tL2FwaS92YS9jcmwv%0AZDEwM2YzODQtNDc0Ny00NWFhLTllYzEtNTE5MTM4NTY0ZjMyMAoGCCqGSM49BAMC%0AA0cAMEQCH0396JDIrwFBsYkHW7g937mpyNWpZhJIxw8x3V4GWvwCIQC5JoFSNyzg%0ALo20QMYX7P2DU0B0smz1u5%2B7cYWl39PiOQ%3D%3D%0A-----END%20CERTIFICATE-----%0A"`)

	logger := logrus.New().WithField("test", "nginx-test")
	extractor := NewEnvoyClientCertificateExtractor(logger)

	crts := extractor.ExtractCertificate(headers)

	if len(crts) != 1 {
		t.Errorf("Expected 1 certificate, got %d", len(crts))
	}

	if crts[0].Subject.CommonName != "Corebox-1" {
		t.Errorf("Expected certificate with CN Corebox-1, got %s", crts[0].Subject.CommonName)
	}
}
