package models

import "crypto/x509"

type ESTAuthMode string

const (
	ESTAuthModeJWT       ESTAuthMode = "JWT"
	ESTAuthModeMutualTLS ESTAuthMode = "MUTUAL_TLS"
)

type ESTServerAuthOptionsMutualTLS struct {
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
