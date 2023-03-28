package models

import "crypto/x509"

type ESTAuthMode string

const (
	NoAuth    ESTAuthMode = "NO_AUTH"
	JWT       ESTAuthMode = "JWT"
	PSK       ESTAuthMode = "PSK"
	MutualTLS ESTAuthMode = "MUTUAL_TLS"
)

type ESTAuthModeBootstapCertificate *x509.Certificate
type ESTAuthModeJWT string
type ESTAuthModeBootstrapPSK string
type ESTAuthModeNoAuth interface{}
