package models

type ESTAuthMode string

const (
	NoAuth    ESTAuthMode = "NO_AUTH"
	JWT       ESTAuthMode = "JWT"
	PSK       ESTAuthMode = "PSK"
	MutualTLS ESTAuthMode = "MUTUAL_TLS"
)

type ESTServerAuthOptionsMutualTLS struct {
	ValidationCAs []string `json:"validation_cas"`
}

type ESTClientAuthOptionsMutualTLS struct {
	Certificate *X509Certificate
	PrivateKey  interface{}
}

type ESTServerAuthOptionJWT struct {
}

type ESTServerAuthOptionPSK struct {
}

const (
	ESTHeaders string = "ESTHeaders"
)
