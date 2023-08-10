package models

import "crypto/x509"

type ESTAuthMode string

const (
	NoAuth    ESTAuthMode = "NO_AUTH"
	JWT       ESTAuthMode = "JWT"
	PSK       ESTAuthMode = "PSK"
	MutualTLS ESTAuthMode = "MUTUAL_TLS"
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
