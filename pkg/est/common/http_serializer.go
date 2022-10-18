package api

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
)

type EnrollSerialized struct {
	Certificate string `json:"certificate"`
}
type EnrollOutputSerialized struct {
	EnrollSerialized
}

func (s *EnrollOutput) Serialize() EnrollSerialized {
	crt := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Cert.Raw})
	encodedCrt := base64.StdEncoding.EncodeToString(crt)
	return EnrollSerialized{
		Certificate: encodedCrt,
	}
}

func (s *EnrollSerialized) Deserialize() EnrollOutput {
	crt, _ := base64.StdEncoding.DecodeString(s.Certificate)
	block, _ := pem.Decode(crt)
	certificate, _ := x509.ParseCertificate(block.Bytes)

	return EnrollOutput{
		Cert: certificate,
	}
}

type ReenrollSerialized struct {
	Certificate string `json:"certificate"`
}
type ReenrollOutputSerialized struct {
	ReenrollSerialized
}

func (s *ReenrollOutput) Serialize() ReenrollSerialized {
	crt := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Cert.Raw})
	encodedCrt := base64.StdEncoding.EncodeToString(crt)
	return ReenrollSerialized{
		Certificate: encodedCrt,
	}
}

func (s *ReenrollSerialized) Deserialize() ReenrollOutput {
	crt, _ := base64.StdEncoding.DecodeString(s.Certificate)
	block, _ := pem.Decode(crt)
	certificate, _ := x509.ParseCertificate(block.Bytes)

	return ReenrollOutput{
		Cert: certificate,
	}
}

type ServerKeyGenSerialized struct {
	Certificate string `json:"certificate"`
}
type ServerKeyGenOutputSerialized struct {
	ServerKeyGenSerialized
}

func (s *ServerKeyGenOutput) Serialize() ServerKeyGenSerialized {
	crt := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Cert.Raw})
	encodedCrt := base64.StdEncoding.EncodeToString(crt)
	return ServerKeyGenSerialized{
		Certificate: encodedCrt,
	}
}

func (s *ServerKeyGenSerialized) Deserialize() ServerKeyGenOutput {
	crt, _ := base64.StdEncoding.DecodeString(s.Certificate)
	block, _ := pem.Decode(crt)
	certificate, _ := x509.ParseCertificate(block.Bytes)

	return ServerKeyGenOutput{
		Cert: certificate,
	}
}
