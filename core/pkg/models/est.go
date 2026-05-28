package models

import "crypto/x509"

type EnrollmentAuthMode string

const (
	EnrollmentAuthModeClientCertificate           EnrollmentAuthMode = "CLIENT_CERTIFICATE"
	EnrollmentAuthModeExternalWebhook             EnrollmentAuthMode = "EXTERNAL_WEBHOOK"
	EnrollmentAuthModeClientCertificateAndWebhook EnrollmentAuthMode = "CLIENT_CERTIFICATE_AND_EXTERNAL_WEBHOOK"
	EnrollmentAuthModeNoAuth                      EnrollmentAuthMode = "NO_AUTH"
)

type ESTServerAuthOptionsClientCertificate struct {
	ClientCertificate *x509.Certificate
}

type ESTServerAuthOptionJWT struct {
}

type ESTServerAuthOptionPSK struct {
}

//Client structs

type ESTClientAuthOptionsMutualTLS struct {
	Certificate *X509Certificate
	PrivateKey  interface{}
}

type EnrollReenrollEvent struct {
	Certificate *X509Certificate `json:"certificate"`
	APS         string           `json:"aps"`
}
