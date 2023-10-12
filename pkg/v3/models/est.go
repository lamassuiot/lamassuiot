package models

import "crypto/x509"

type ESTAuthMode string

const (
	ESTAuthModeNoAuth    ESTAuthMode = "NO_AUTH"
	ESTAuthModeMutualTLS ESTAuthMode = "MUTUAL_TLS"
)

const (
	ESTServerKeyGenBitSize = "ESTServerKeyGenBitSize"
	ESTServerKeyGenKeyType = "ESTServerKeyGenKeyType"
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
