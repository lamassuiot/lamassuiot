package models

import "crypto/x509"

type ESTAuthMode string

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
