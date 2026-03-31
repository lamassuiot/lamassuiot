package identityextractors

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func TestClientCertificateIdentityExtractorHeaderEnvoy(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://localhost", nil)
	req.Header.Add("x-forwarded-client-cert", `Hash=d646c40e86509aafb2872b88b2fe0fbf3e878c3cb9c83b1edec562177e7c96fd;Chain="-----BEGIN%20CERTIFICATE-----%0AMIID7jCCAtagAwIBAgIRAJu1DlsfCgK%2FKrWM23BvYdIwDQYJKoZIhvcNAQELBQAw%0AFDESMBAGA1UEAxMJRmFjdG9yeSAxMB4XDTI2MDMzMTExMTkzOVoXDTMxMDMyNTEx%0AMTkzOVowDzENMAsGA1UEAxMEdGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC%0AAQoCggEBAN%2FKHvD%2BtdA6wxtqb77gqDjPzlNmQsW5co4hxsetjlKSZjMGzWtNd7Jh%0AgZ7kIvpCParjd0k9bVbRXfudGcJYaG%2BZMDrB31PcpITt2e4m%2BeJCUabIMyCxu2k6%0Ax8uAxWiWUAEKfnIDY0m%2BBZyzdNU404PvhuFDhrhz0xNspDyaIT0u0zpH%2FqQcmYvO%0Agp0Sw%2FkF4%2FZ92JMzLi7tlSFZFmOoMr1UI4MPwHLKuvrm6eeVHdfos54tqf7j9%2FJK%0APlYr%2FFTqvcFg40jxvs5xaOqWOaf6TjqxKm4xnBwN7%2FivCKFe1ZgRAf%2Bqe6JCg%2BNH%0Ae1mDX55ZBTIvAgZurTnu71bUglmWsDsCAwEAAaOCAT4wggE6MA4GA1UdDwEB%2FwQE%0AAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwKQYDVR0OBCIEIFp6%0APKIfygwgFooYDUQB4Mm4NkVFHQ1Yzg5EFJHW31wSMCsGA1UdIwQkMCKAIHptqEro%0Al70gDiudUEowVqaPirFae3Kn57oLsHYorO2GMD0GCCsGAQUFBwEBBDEwLzAtBggr%0ABgEFBQcwAYYhaHR0cDovL2xhYi5sYW1hc3N1LmlvL2FwaS92YS9vY3NwMHIGA1Ud%0AHwRrMGkwZ6BloGOGYWh0dHA6Ly9sYWIubGFtYXNzdS5pby9hcGkvdmEvY3JsLzdh%0ANmRhODRhZTg5N2JkMjAwZTJiOWQ1MDRhMzA1NmE2OGY4YWIxNWE3YjcyYTdlN2Jh%0AMGJiMDc2MjhhY2VkODYwDQYJKoZIhvcNAQELBQADggEBAEcLrqIw2kuuNlIl9pqp%0AeBrYRE9tSqfAKSKMeEcW%2BbqObYQec0VDjuvgTSdgGWlOlnrVnVOOw6ANp%2F1%2BEJlU%0A%2Brt%2B9qfoewIvX7bQ2Wr0BAq%2BNUGPppXJzCMgm4KrzRY5BIPfwFU0CspX%2B3WJI%2BZ2%0A%2FqQ2dV9QVs2gpzzqbYe6GTQh9c844u4aPLEn7WdWM4N%2Fls6yt%2BjVxKU3OaIj9by7%0AdtbZDnIc6DIa%2BUz1zKMzknY4OpRfgfNEQh7nWTINMZ3FfukcolIoCQFoUiLiJ2SQ%0ApzkJX8iW7suq4DX07Gb8l8usuww6e1roQ2UjhKGqjAhzDnWf6mSIqIF96G1W8o0X%0Ax74%3D%0A-----END%20CERTIFICATE-----%0A-----BEGIN%20CERTIFICATE-----%0AMIIEOTCCAyGgAwIBAgIQSaEa8nyQQwD9DBxh7JhEZzANBgkqhkiG9w0BAQsFADBp%0AMQswCQYDVQQGEwJFUzERMA8GA1UEBxMIQXJyYXNhdGUxEDAOBgNVBAoMB0lLRVJf%0AS1MxFjAUBgNVBAsTDW1hbnVmY2F0dXJpbmcxHTAbBgNVBAMTFE1hbnVmYWN0dXJp%0AbmcgSURzIENBMB4XDTI2MDMyNjIwNDQzM1oXDTMxMDMyMDIwNDQzM1owFDESMBAG%0AA1UEAxMJRmFjdG9yeSAxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA%0A1vdWfefR%2Fz1vR%2BORCH017UdeVS53NySHE2kWqaOVGS6AmpgO56sXDaKbhs6BVRDG%0AQKrd5KdPlpU3%2BS5%2BrhQcS1bVWGV7gNcVbxHZLy28SujniW1Ph4tlcIpYp6oglPDE%0AWZGc8RJoFz%2FTSVnV4NNYygVesY1Sqo2mcN5G5tRRXYIf09i%2Ft1WHvHzyamOq5XsO%0AGsbPBklylGZHWlhG6BwrOxwQIyYGSfsOdfhmBfNxeYJzmxG5mmo9ecJmLZihWlkH%0Al7N8J18Bh38soGph8CyoF26payv%2B70KrNTgp7a1YHX3l9dNgSfFLnIJUTY4H1yVF%0AcGUsO1KcJA108pDMkU1sSwIDAQABo4IBMDCCASwwDgYDVR0PAQH%2FBAQDAgEGMA8G%0AA1UdEwEB%2FwQFMAMBAf8wKQYDVR0OBCIEIHptqErol70gDiudUEowVqaPirFae3Kn%0A57oLsHYorO2GMCsGA1UdIwQkMCKAICDYs9F1pD%2Buj8zinYxo2AZanhKjMUM2k8Xd%0AkeMO7PsbMD0GCCsGAQUFBwEBBDEwLzAtBggrBgEFBQcwAYYhaHR0cDovL2xhYi5s%0AYW1hc3N1LmlvL2FwaS92YS9vY3NwMHIGA1UdHwRrMGkwZ6BloGOGYWh0dHA6Ly9s%0AYWIubGFtYXNzdS5pby9hcGkvdmEvY3JsLzIwZDhiM2QxNzVhNDNmYWU4ZmNjZTI5%0AZDhjNjhkODA2NWE5ZTEyYTMzMTQzMzY5M2M1ZGQ5MWUzMGVlY2ZiMWIwDQYJKoZI%0AhvcNAQELBQADggEBAH5jAVE32JLbpAj48ymp757uG1h8hTLC5tSOcgvihWEm0UWS%0AXq5Y2mXv6gY%2FG%2B2qkul86FCScAvSsFKuYYEJxudKFluOjLIVoxdxG%2BdOmy8b2zsp%0AIjc3EQOMj5yTH%2B6otdH2KJp9tEhvs8oZLbgmn5YoYnShb6Hd24G8JptYee75NcMV%0A0VzUbioSaZAWcS7NPJyK36O1Yp%2BbXPZBrWOg4tkZJHHqJYhxsjufx0UiS16diPdN%0Akka6PHmd41RSZiO0GG8EhLjUEsVhgnlldZAXxHqxQj5JFEr4BGj4foCGH68wFTL%2F%0AhOUv1UWBKXCSOjp2pzgZnf4D9XQBmD%2BLvIApXSA%3D%0A-----END%20CERTIFICATE-----%0A"`)

	logger := logrus.New().WithField("test", "test")

	extractor := ClientCertificateExtractor{
		logger: logger,
	}

	ctx := &gin.Context{}
	extractor.ExtractAuthentication(ctx, *req)

	value, hasValue := ctx.Get(string(IdentityExtractorClientCertificate))
	if !hasValue {
		t.Errorf("Expected certificate, got nil")
	}

	crts, ok := value.([]*x509.Certificate)
	if !ok {
		t.Errorf("Expected certificate, got %T", value)
	}

	fmt.Println(crts[1].Subject.CommonName)

	if crts[0].Subject.CommonName != "test" {
		t.Errorf("Expected certificate with CN test, got %s", crts[0].Subject.CommonName)
	}

	if crts[1].Subject.CommonName != "Factory 1" {
		t.Errorf("Expected certificate with CN Factory 1, got %s", crts[1].Subject.CommonName)
	}
}

func TestClientCertificateIdentityExtractorHeaderNginx(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://localhost", nil)
	req.Header.Set("ssl-client-cert", "-----BEGIN%20CERTIFICATE-----%0AMIIDdTCCAxygAwIBAgIQX0L1bVPmFg5lLX1OuqlA0jAKBggqhkjOPQQDAjBnMQsw%0ACQYDVQQGEwJFUzERMA8GA1UECBMIR2lwdXprb2ExEDAOBgNVBAcTB0JlYXNhaW4x%0AEjAQBgNVBAoTCUdIIENyYW5lczEfMB0GA1UEAxMWR0ggQ29yZWJveCBJZGVudGl0%0AeSBDQTAeFw0yNDA3MTcxMDUwMDNaFw0yNjA3MTUxMDUwMDNaMDUxCzAJBgNVBAYT%0AAkVTMRIwEAYDVQQKEwlHSCBDcmFuZXMxEjAQBgNVBAMTCUNvcmVib3gtMTCCASIw%0ADQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKmEIfcVbkcwH0%2Bij9yCapYoWfzK%0A%2FUBIlYtaLMRqeFPT84ajjDcGrqcLvbJFifjyPzWnN4pl4enpdygHPaKVQC5ryWKS%0ACbGwlbDhgDfv%2B2eah1J6mp%2Bk9Hnll2AyrpIkQ2nSAvFLFSwwU7l3yccJqfozHPwP%0A%2FCDpupljivM3kk1mPcZn5IkzeIQBxDcGP%2FV2cTjSxx6viClMWXbQs48ub1WDp%2Bu6%0AaB8fyTOSlPqSTartP0QMnyHmPOIASm6zrQ36aWRrMuYOaIokwGcLogluMzW8L8nz%0AwJo9qi6%2FI5mDCHOz7K3a8ybuQmtjATVjz1cCNxyLT76UKAvBg94j6sBb51UCAwEA%0AAaOCAQ8wggELMA4GA1UdDwEB%2FwQEAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAgYI%0AKwYBBQUHAwEwLwYDVR0jBCgwJoAkZDEwM2YzODQtNDc0Ny00NWFhLTllYzEtNTE5%0AMTM4NTY0ZjMyMEcGCCsGAQUFBwEBBDswOTA3BggrBgEFBQcwAYYraHR0cHM6Ly9s%0AYW1zc3UtZGV2LmdoY3JhbmVzLmNvbS9hcGkvdmEvb2NzcDBgBgNVHR8EWTBXMFWg%0AU6BRhk9odHRwczovL2xhbXNzdS1kZXYuZ2hjcmFuZXMuY29tL2FwaS92YS9jcmwv%0AZDEwM2YzODQtNDc0Ny00NWFhLTllYzEtNTE5MTM4NTY0ZjMyMAoGCCqGSM49BAMC%0AA0cAMEQCH0396JDIrwFBsYkHW7g937mpyNWpZhJIxw8x3V4GWvwCIQC5JoFSNyzg%0ALo20QMYX7P2DU0B0smz1u5%2B7cYWl39PiOQ%3D%3D%0A-----END%20CERTIFICATE-----%0A")

	logger := logrus.New().WithField("test", "test")

	extractor := ClientCertificateExtractor{
		logger: logger,
	}

	ctx := &gin.Context{}
	extractor.ExtractAuthentication(ctx, *req)

	value, hasValue := ctx.Get(string(IdentityExtractorClientCertificate))
	if !hasValue {
		t.Errorf("Expected certificate, got nil")
	}

	crts, ok := value.([]*x509.Certificate)
	if !ok {
		t.Errorf("Expected certificate, got %T", value)
	}

	if crts[0].Subject.CommonName != "Corebox-1" {
		t.Errorf("Expected certificate with CN Corebox-1, got %s", crts[0].Subject.CommonName)
	}
}

func TestClientCertificateIdentityExtractorHeaderAwsALB(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://localhost", nil)
	req.Header.Set("X-Amzn-Mtls-Clientcert", "-----BEGIN%20CERTIFICATE-----%0AMIIDSTCCAu+gAwIBAgIRAJ+9uWWKS6H1SvR7npYKgewwCgYIKoZIzj0EAwIwZTEQ%0AMA4GA1UEBgwHRXNwYcOxYTERMA8GA1UECBMIR2lwdXpjb2ExDzANBgNVBAcMBk/D%0AsWF0aTEPMA0GA1UEChMGQ2VnYXNhMRwwGgYDVQQDExNFQ1MgTWFudWZhY3R1cmVy%0AIENBMCAXDTI1MDMxNDExNTExOVoYDzIwNTUwMjA1MTE1MTE5WjAhMR8wHQYDVQQD%0AExZ1aS1nZW5lcmF0ZWQtYm9vdHN0cmFwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A%0AMIIBCgKCAQEAyG3FYpRRUu9ypNN4/p5bjNHyZvqoujke1wpwpoKRk1gkTZRGbW+3%0Ab0sTiQBstrydlxyTpuQh+W+O8qWwWhkTdOqLNEvtsACazUsozVaxkcAnNViSq+K7%0A2g1qBFHCpulF36MyKu8cRX/MoYSzd3fKcCMpb/JWZvvuivLiKQYv92b0jHONQlYT%0AIT9gAEfhGQraknFohiZh4XwHFukWE80djlS++uVc+de5grQtsaFJujUTA0HctAgT%0Aj/SjJoxDrCZomTZ4xt8Zn4u7YUlcmfX3XDmIM2WIFLU7ckW9/wsZaGh2F0HBTa3m%0A8G58al3IdbdmsqmjSDFbzNmcjghtfCiz1QIDAQABo4H2MIHzMA4GA1UdDwEB/wQE%0AAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwLwYDVR0jBCgwJoAk%0AYTg2OTc1OTAtNjY1Ny00ZmJkLWI4ODItNjE1YzhjMGQ5NzQzMDsGCCsGAQUFBwEB%0ABC8wLTArBggrBgEFBQcwAYYfaHR0cHM6Ly9sYW1hc3N1LmRldi9hcGkvdmEvb2Nz%0AcDBUBgNVHR8ETTBLMEmgR6BFhkNodHRwczovL2xhbWFzc3UuZGV2L2FwaS92YS9j%0AcmwvYTg2OTc1OTAtNjY1Ny00ZmJkLWI4ODItNjE1YzhjMGQ5NzQzMAoGCCqGSM49%0ABAMCA0gAMEUCIQDlB8nx7oECZSD4kSgEaOuw4Q26er4m3vU0FEkf6/ZXjwIgUUkR%0AYNNLOwJ+cpeDH6IyzFIvA1V7RcKcqNGki7s5fis=%0A-----END%20CERTIFICATE-----%0A")

	logger := logrus.New().WithField("test", "test")

	extractor := ClientCertificateExtractor{
		logger: logger,
	}

	ctx := &gin.Context{}
	extractor.ExtractAuthentication(ctx, *req)

	value, hasValue := ctx.Get(string(IdentityExtractorClientCertificate))
	if !hasValue {
		t.Errorf("Expected certificate, got nil")
	}

	crts, ok := value.([]*x509.Certificate)
	if !ok {
		t.Errorf("Expected certificate, got %T", value)
	}

	if crts[0].Subject.CommonName != "ui-generated-bootstrap" {
		t.Errorf("Expected certificate with CN ui-generated-bootstrap, got %s", crts[0].Subject.CommonName)
	}
}

func TestClientCertificateIdentityExtractorPeerTLS(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://localhost", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{
				Subject: pkix.Name{
					CommonName: "Corebox-1",
				},
			},
		},
	}

	logger := logrus.New().WithField("test", "test")

	extractor := ClientCertificateExtractor{
		logger: logger,
	}

	ctx := &gin.Context{}
	extractor.ExtractAuthentication(ctx, *req)

	value, hasValue := ctx.Get(string(IdentityExtractorClientCertificate))
	if !hasValue {
		t.Errorf("Expected certificate, got nil")
	}

	crts, ok := value.([]*x509.Certificate)
	if !ok {
		t.Errorf("Expected certificate, got %T", value)
	}

	if crts[0].Subject.CommonName != "Corebox-1" {
		t.Errorf("Expected certificate with CN Corebox-1, got %s", crts[0].Subject.CommonName)
	}
}

func TestClientCertificateIdentityExtractorNoID(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://localhost", nil)

	logger := logrus.New().WithField("test", "test")

	extractor := ClientCertificateExtractor{
		logger: logger,
	}

	ctx := &gin.Context{}
	extractor.ExtractAuthentication(ctx, *req)

	_, hasValue := ctx.Get(string(IdentityExtractorClientCertificate))
	if hasValue {
		t.Errorf("Expected no certificate, got one")
	}
}
