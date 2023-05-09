package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net/url"

	_ "github.com/go-kivik/couchdb/v4" // The CouchDB driver
	"github.com/jakehl/goid"
	lamassuEstClient "github.com/lamassuiot/lamassuiot/pkg/est/client"
)

func main() {
	bootCert := `-----BEGIN CERTIFICATE-----
MIIFKTCCA5GgAwIBAgIUF0dgs+Qtej0V3Ct8MdWNAksrDBcwDQYJKoZIhvcNAQEL
BQAwGDEWMBQGA1UEAxMNQm9vdHN0cmFwUENPTTAeFw0yMzAyMjMxMzE5NTRaFw0y
MzA2MDMxMzIwMjRaMGUxCzAJBgNVBAYTAkVTMQ8wDQYDVQQIEwZHaXB1emsxETAP
BgNVBAcTCEFycmFzYXRlMRAwDgYDVQQKEwdJa2VybGFuMQwwCgYDVQQLEwNaUEQx
EjAQBgNVBAMTCWJvb3RzdHJhcDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
ggIBAMP+tImJHp9yFxtEckVgNZedOugS/iavyLk/AZ50MvpxAPoFVGYib69XkIEX
FFCMrhe9NdfTjYYceUC+KM6d0mjdpTQE6KwkaQcVA3ZQkXI5C+uKboOi7ZAUHXfl
QfZsDbK9ZK6a2zckb5V5rHGu2ImZ3BhJYdS3i3QNCy9LH2hw/VxIoMaFjzPyl6Li
uWZ8ArXoLq0cUHoeN1RM9uDYTDTVwD9LRSzSpYe0QevX0P87W81JIOVq8sApGU/+
6ZKBc440VgSvh9oeBczFKzANip76b/qPtiSXFDSWAnglqy9Usq0YQ9WbsggXCAUx
2ALwVla2JK0VdfNTQaVdCCSEA5nt6Lw4Prs7Ad1tnLsUIcHUsDI349auXrelSYnD
ydrIseFO7t6TvfVro5uA0xx79DMDLAGd8LLzTnkdGpPeucw+xAo0OoaZ5o7jZXf2
nNWYpRwHxtxTfFBym7Lr8T9EJVLn6Xp8v/8b2tlkGeBhlmNXafRbR2yWWoHG+vtF
91IV+UpM6lNdTsuVAG0ALaK5+bdF9gw/379LHSlpVKHjVqhRL/vLWe2cHv0fqnzL
9K16WyJjVl9n987HQ5e6r3T301Eyj+bSiajZBQTUcrowe91I/Ho15T0V9SndQMnj
MbWvGpTfK5dv4iau/ldHz1s1/iw5em4wdit4lig+IBiW5kq7AgMBAAGjgZ0wgZow
DgYDVR0PAQH/BAQDAgOoMB0GA1UdDgQWBBRQ9rzgskVC3ZSeiHP+NZchcOaRJDAf
BgNVHSMEGDAWgBQZN/EpqbcR4S8sIYM6z9k+XT9yMTBIBggrBgEFBQcBAQQ8MDow
OAYIKwYBBQUHMAGGLGh0dHBzOi8vZGV2LmxhbWFzc3UuenBkLmlrZXJsYW4uZXMv
YXBpL29jc3AvMA0GCSqGSIb3DQEBCwUAA4IBgQBEfMWMChjzwB1zvDu/FAbx0IEB
Go8SascVo6Ts4u2tfQ4TOlApsB4TGkUPhjLnwNTiwtOcJQdTOnjw+RFGh87MP+Rs
PcZcpBDDaEss62YmbdkYNIWWZo9mABganWXyaWqDrvCntVrAae9MOmmTJySWxTHy
f5r+1B8ndPNkZk/J2IJzmZitJwvKO5UkPTxeyZrdslOY1c0z0Q2shcxEWeQsXFS5
5WIzU/4XoVLiH9PKBr366dEy/hbJJe2/N0tzGeUbXTEQJCcsUx+M84XihhyS0ZP2
tsoM6uv5EyrBXoEcd1fWtt5M3eHRblQK7vf0qqTtUjj6j0usBqxqAz2F8BK+uRlV
AC+hSRnKIiviN0IvNOhNOWk1XyD0auE7BjkPjm9kytR2p+llT2JngUl00q2BmmWe
DeU15GtSc30kdhkBPqB/kGCWFTPkFnQvGzcVPmPPyb4rYdq3eoc1OOM719LWTrj9
BS+vce/8CP4mZkYKB7SRUhyT2YFVnykSLC3jSzo=
-----END CERTIFICATE-----
	`

	apiGWKey := `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINAmR1g2/4rDny7JyJ181992aWGhWMmxeDUlLHb+mj2doAoGCCqGSM49
AwEHoUQDQgAE2sA7DD7pnm+HufBFCqAf6bUiOP3N+V3rmGQ61vD3pl80zGmGmWuW
pJSx2g7dPzyxXEsoziPMapWVi+yj0Lsedg==
-----END EC PRIVATE KEY-----
	`
	apiGWCert := `-----BEGIN CERTIFICATE-----
MIIBjDCCATKgAwIBAgIRAODkUXH7UmL6480LO2Ex0cAwCgYIKoZIzj0EAwIwHjEc
MBoGA1UEAxMTaW50ZXJuYWwtbGFtYXNzdS1jYTAeFw0yMzAyMjAxODQyNThaFw0y
MzA1MjExODQyNThaMBYxFDASBgNVBAMTC2FwaS1nYXRld2F5MFkwEwYHKoZIzj0C
AQYIKoZIzj0DAQcDQgAE2sA7DD7pnm+HufBFCqAf6bUiOP3N+V3rmGQ61vD3pl80
zGmGmWuWpJSx2g7dPzyxXEsoziPMapWVi+yj0LsedqNZMFcwDgYDVR0PAQH/BAQD
AgWgMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUOoWeMDrgayTZcApsqiU2kRNf
brswFgYDVR0RBA8wDYILYXBpLWdhdGV3YXkwCgYIKoZIzj0EAwIDSAAwRQIgBBC0
omQecY7ATBLU93vYoQMqh7+su5pnJYh8LjnAwvgCIQDsaWvA9WYu+AzfCsgdHqXD
XfSvX9gF5yNMrnFrBWO7Bw==
-----END CERTIFICATE-----
	`

	cpb, _ := pem.Decode([]byte(bootCert))
	bootstrapCert, err := x509.ParseCertificate(cpb.Bytes)
	if err != nil {
		panic(err)
	}

	cpb, _ = pem.Decode([]byte(apiGWCert))
	apiGWCertificate, err := x509.ParseCertificate(cpb.Bytes)
	if err != nil {
		panic(err)
	}

	kpb, _ := pem.Decode([]byte(apiGWKey))
	apiGWECKey, err := x509.ParseECPrivateKey(kpb.Bytes)
	if err != nil {
		panic(err)
	}

	estcli, err := lamassuEstClient.NewESTClient(nil, &url.URL{
		Scheme: "https",
		Host:   "dev-lamassu.zpd.ikerlan.es:8085",
	}, apiGWCertificate, apiGWECKey, nil, true)
	if err != nil {
		panic(err)
	}

	_, csr := generateCertificateRequestAndKey("PCOM-" + goid.NewV4UUID().String())

	ctx := context.Background()
	ctx = context.WithValue(ctx, lamassuEstClient.WithXForwardedClientCertHeader, bootstrapCert)

	crt, err := estcli.Enroll(ctx, "PCOM_v1", csr)
	if err != nil {
		panic(err)
	}

	fmt.Println(crt)
}

func generateCertificateRequestAndKey(commonName string) (*rsa.PrivateKey, *x509.CertificateRequest) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	csr := generateCertificateRequest(commonName, key)
	return key, csr
}

func generateCertificateRequest(commonName string, key *rsa.PrivateKey) *x509.CertificateRequest {
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		panic(err)
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		panic(err)
	}

	return csr
}
