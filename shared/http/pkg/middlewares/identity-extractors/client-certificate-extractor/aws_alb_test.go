package clientcertificateextractor

import (
	"net/http"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestAwsALBCertExtraction(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-Amzn-Mtls-Clientcert", "-----BEGIN%20CERTIFICATE-----%0AMIIDSTCCAu+gAwIBAgIRAJ+9uWWKS6H1SvR7npYKgewwCgYIKoZIzj0EAwIwZTEQ%0AMA4GA1UEBgwHRXNwYcOxYTERMA8GA1UECBMIR2lwdXpjb2ExDzANBgNVBAcMBk/D%0AsWF0aTEPMA0GA1UEChMGQ2VnYXNhMRwwGgYDVQQDExNFQ1MgTWFudWZhY3R1cmVy%0AIENBMCAXDTI1MDMxNDExNTExOVoYDzIwNTUwMjA1MTE1MTE5WjAhMR8wHQYDVQQD%0AExZ1aS1nZW5lcmF0ZWQtYm9vdHN0cmFwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A%0AMIIBCgKCAQEAyG3FYpRRUu9ypNN4/p5bjNHyZvqoujke1wpwpoKRk1gkTZRGbW+3%0Ab0sTiQBstrydlxyTpuQh+W+O8qWwWhkTdOqLNEvtsACazUsozVaxkcAnNViSq+K7%0A2g1qBFHCpulF36MyKu8cRX/MoYSzd3fKcCMpb/JWZvvuivLiKQYv92b0jHONQlYT%0AIT9gAEfhGQraknFohiZh4XwHFukWE80djlS++uVc+de5grQtsaFJujUTA0HctAgT%0Aj/SjJoxDrCZomTZ4xt8Zn4u7YUlcmfX3XDmIM2WIFLU7ckW9/wsZaGh2F0HBTa3m%0A8G58al3IdbdmsqmjSDFbzNmcjghtfCiz1QIDAQABo4H2MIHzMA4GA1UdDwEB/wQE%0AAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwLwYDVR0jBCgwJoAk%0AYTg2OTc1OTAtNjY1Ny00ZmJkLWI4ODItNjE1YzhjMGQ5NzQzMDsGCCsGAQUFBwEB%0ABC8wLTArBggrBgEFBQcwAYYfaHR0cHM6Ly9sYW1hc3N1LmRldi9hcGkvdmEvb2Nz%0AcDBUBgNVHR8ETTBLMEmgR6BFhkNodHRwczovL2xhbWFzc3UuZGV2L2FwaS92YS9j%0AcmwvYTg2OTc1OTAtNjY1Ny00ZmJkLWI4ODItNjE1YzhjMGQ5NzQzMAoGCCqGSM49%0ABAMCA0gAMEUCIQDlB8nx7oECZSD4kSgEaOuw4Q26er4m3vU0FEkf6/ZXjwIgUUkR%0AYNNLOwJ+cpeDH6IyzFIvA1V7RcKcqNGki7s5fis=%0A-----END%20CERTIFICATE-----%0A")

	logger := logrus.New().WithField("test", "aws-alb-test")
	extractor := NewAwsALBClientCertificateExtractor(logger)

	crts := extractor.ExtractCertificate(headers)

	if len(crts) != 1 {
		t.Errorf("Expected 1 certificate, got %d", len(crts))
	}

	if crts[0].Subject.CommonName != "ui-generated-bootstrap" {
		t.Errorf("Expected certificate with CN ui-generated-bootstrap, got %s", crts[0].Subject.CommonName)
	}
}

func TestAwsALBCertExtractionCorrupt(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-Amzn-Mtls-Clientcert", "-----BEGIN%20CERTIFICATE-----%0AMIIDdTCCAxygAwIBAgIQX0L1bVPmFg5lLX1Ouq0A0jAKBggqhkjOPQQDAjBnMQsw%0ACQYDVQQGEwJFUzERMA8GA1UECBMIR2lwdXprb2ExEDAOBgNVBAcTB0JlYXNhaW4x%0AEjAQBgNVBAoTCUdIIENyYW5lczEfMB0GA1UEAxMWR0ggQ29yZWJveCBJZGVudGl0%0AeSBDQTAeFw0yNDA3MTcxMDUwMDNaFw0yNjA3MT1cMDUwMDNaMDUxCzAJBgNVBAYT%0AAkVTMRIwEAYDVQQKEwlHSCBDcmFuZXMxEjAQBgNVBAMTCUNvcmVib3gtMTCCASIw%0ADQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKmEIfcVbkcwH0%2Bij9yCapYoWfzK%0A%2FUBIlYtaLMRqeFPT84ajjDcGrqcLvbJFifjyPzWnN4pl4enpdygHPaKVQC5ryWKS%0ACbGwlbDhgDfv%2B2eah1J6mp%2Bk9Hnll2AyrpIkQ2nSAvFLFSwwU7l3yccJqfozHPwP%0A%2FCDpupljivM3kk1mPcZn5IkzeIQBxDcGP%2FV2cTjSxx6viClMWXbQs48ub1WDp%2Bu6%0AaB8fyTOSlPqSTartP0QMnyHmPOIASm6zrQ36aWRrMuYOaIokwGcLogluMzW8L8nz%0AwJo9qi6%2FI5mDCHOz7K3a8ybuQmtjATVjz1cCNxyLT76UKAvBg94j6sBb51UCAwEA%0AAaOCAQ8wggELMA4GA1UdDwEB%2FwQEAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAgYI%0AKwYBBQUHAwEwLwYDVR0jBCgwJoAkZDEwM2YzODQtNDc0Ny00NWFhLTllYzEtNTE5%0AMTM4NTY0ZjMyMEcGCCsGAQUFBwEBBDswOTA3BggrBgEFBQcwAYYraHR0cHM6Ly9s%0AYW1zc3UtZGV2LmdoY3JhbmVzLmNvbS9hcGkvdmEvb2NzcDBgBgNVHR8EWTBXMFWg%0AU6BRhk9odHRwczovL2xhbXNzdS1kZXYuZ2hjcmFuZXMuY29tL2FwaS92YS9jcmwv%0AZDEwM2YzODQtNDc0Ny00NWFhLTllYzEtNTE5MTM4NTY0ZjMyMAoGCCqGSM49BAMC%0AA0cAMEQCH0396JDIrwFBsYkHW7g937mpyNWpZhJIxw8x3V4GWvwCIQC5JoFSNyzg%0ALo20QMYX7P2DU0B0smz1u5%2B7cYWl39PiOQ%3D%3D%0A-----END%20CERTIFICATE-----%0A")

	logger := logrus.New().WithField("test", "aws-alb-test")
	extractor := NewAwsALBClientCertificateExtractor(logger)

	crts := extractor.ExtractCertificate(headers)

	if len(crts) != 0 {
		t.Errorf("Expected 0 certificates, got %d", len(crts))
	}
}

func TestAwsALBCertExtractionEmpty(t *testing.T) {
	headers := http.Header{}

	logger := logrus.New().WithField("test", "aws-alb-test")
	extractor := NewAwsALBClientCertificateExtractor(logger)

	crts := extractor.ExtractCertificate(headers)

	if len(crts) != 0 {
		t.Errorf("Expected 0 certificates, got %d", len(crts))
	}
}
