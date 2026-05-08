package models

import "crypto/x509"

type ESTAuthMode string

const (
	ESTAuthModeClientCertificate                ESTAuthMode = "CLIENT_CERTIFICATE"
	ESTAuthModeNoAuth                           ESTAuthMode = "NO_AUTH"
	ESTAuthModeExternalWebhook                  ESTAuthMode = "EXTERNAL_WEBHOOK"
	ESTAuthModeClientCertificateExternalWebhook ESTAuthMode = "CLIENT_CERTIFICATE_EXTERNAL_WEBHOOK"
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
