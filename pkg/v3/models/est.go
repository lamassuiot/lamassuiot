package models

import "crypto/x509"

type ESTAuthMode string

const (
	ESTAuthModeNoAuth            ESTAuthMode = "NO_AUTH"
	ESTAuthModeClientCertificate ESTAuthMode = "CLIENT_CERTIFICATE"
)

const (
	ESTServerKeyGenBitSize = "ESTServerKeyGenBitSize"
	ESTServerKeyGenKeyType = "ESTServerKeyGenKeyType"
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
