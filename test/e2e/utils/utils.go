package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/csv"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

func WriteFile(file *os.File, data [][]string) error {
	writer := csv.NewWriter(file)
	err := writer.WriteAll(data)
	if err != nil {
		fmt.Println(err)
		return err
	}
	return nil
}

func GenrateRandKey(id string) ([]byte, *x509.CertificateRequest, error) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	privKey, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		return nil, nil, err
	}
	csr, err := GenerateCSR(rsaKey, "rsa", id)
	if err != nil {
		return nil, nil, err
	}
	return privKey, csr, nil
}

func GenerateCSR(key interface{}, Keytype string, id string) (*x509.CertificateRequest, error) {
	subj := pkix.Name{
		Country:            []string{"ES"},
		Province:           []string{"Gipuzkoa"},
		Organization:       []string{"IKERLAN"},
		OrganizationalUnit: []string{"ZPD"},
		Locality:           []string{"Arrasate"},
		CommonName:         id,
	}
	rawSubject := subj.ToRDNSequence()
	asn1Subj, _ := asn1.Marshal(rawSubject)
	var template x509.CertificateRequest
	if Keytype == "rsa" {
		template = x509.CertificateRequest{
			RawSubject:         asn1Subj,
			SignatureAlgorithm: x509.SHA512WithRSA,
		}
	} else {
		template = x509.CertificateRequest{
			RawSubject:         asn1Subj,
			SignatureAlgorithm: x509.ECDSAWithSHA512,
		}
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %v", err)
	}
	csrNew, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate request: %v", err)
	}
	return csrNew, nil
}

func WriteDataFile(id string, max float64, min float64, media float64, file *os.File) error {
	var data = [][]string{
		{id, fmt.Sprint(max), fmt.Sprint(min), fmt.Sprint(media)},
	}
	err := WriteFile(file, data)
	if err != nil {
		return err
	}
	return nil
}

func StringToCSR(s string) (*x509.CertificateRequest, error) {
	csr2Str := s
	data2, _ := base64.StdEncoding.DecodeString(csr2Str)
	block2, _ := pem.Decode([]byte(data2))
	c, err := x509.ParseCertificateRequest(block2.Bytes)
	return c, err
}
func InsertCert(path string, data []byte) {
	f, _ := os.Create(path)
	b := pem.Block{Type: "CERTIFICATE", Bytes: data}
	certPEM := pem.EncodeToMemory(&b)
	f.Write(certPEM)
	f.Close()
}

func InsertKey(path string, data []byte) {
	f, _ := os.Create(path)
	b := pem.Block{Type: "PRIVATE KEY", Bytes: data}
	keyPEM := pem.EncodeToMemory(&b)
	f.Write(keyPEM)
	f.Close()
}
func InsertCsr(path string, data []byte) {
	f, _ := os.Create(path)
	b := pem.Block{Type: "CERTIFICATE REQUEST", Bytes: data}
	certPEM := pem.EncodeToMemory(&b)
	f.Write(certPEM)
	f.Close()
}

func ReadCertPool(path string) (*x509.CertPool, error) {
	caCert, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	return caCertPool, nil
}
func ReadCert(path string) (*x509.Certificate, error) {
	certContent, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cpb, _ := pem.Decode(certContent)

	crt, err := x509.ParseCertificate(cpb.Bytes)
	if err != nil {
		return nil, err
	}
	return crt, nil
}

func ReadKey(path string) ([]byte, error) {
	key, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return key, nil
}
