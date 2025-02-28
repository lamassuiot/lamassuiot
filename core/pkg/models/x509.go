package models

import (
	"crypto/x509"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// --------------------------------------------
type X509Certificate x509.Certificate

func (c *X509Certificate) String() string {
	res, err := c.MarshalJSON()
	if err != nil {
		return ""
	}

	certString := strings.ReplaceAll(string(res), "\"", "")

	return string(certString)
}

func (c *X509Certificate) MarshalJSON() ([]byte, error) {
	data := []byte{}

	if c != nil {
		pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
		data = make([]byte, base64.StdEncoding.EncodedLen(len(pemCert)))
		base64.StdEncoding.Encode(data, pemCert)
		return json.Marshal(string(data))
	}

	return json.Marshal(data)
}

func (c *X509Certificate) UnmarshalJSON(data []byte) error {
	var decodedCert []byte
	err := json.Unmarshal(data, &decodedCert)
	if err != nil {
		return err
	}

	certBlock, _ := pem.Decode(decodedCert)
	if certBlock != nil {
		certificate, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return err
		}

		*c = X509Certificate(*certificate)
		return nil
	}

	return fmt.Errorf("missing cert block")
}

// --------------------------------------------
type X509CertificateRequest x509.CertificateRequest

func (c *X509CertificateRequest) String() string {
	res, err := c.MarshalJSON()
	if err != nil {
		return ""
	}

	certString := strings.ReplaceAll(string(res), "\"", "")

	return string(certString)
}

func (c *X509CertificateRequest) MarshalJSON() ([]byte, error) {
	data := []byte{}

	if c != nil {
		pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: c.Raw})
		data = make([]byte, base64.StdEncoding.EncodedLen(len(pemCert)))
		base64.StdEncoding.Encode(data, pemCert)
		return json.Marshal(string(data))
	}

	return json.Marshal(data)
}

func (c *X509CertificateRequest) UnmarshalJSON(data []byte) error {
	var decodedCert []byte
	err := json.Unmarshal(data, &decodedCert)
	if err != nil {
		return err
	}

	certBlock, _ := pem.Decode(decodedCert)
	if certBlock != nil {
		certificate, err := x509.ParseCertificateRequest(certBlock.Bytes)
		if err != nil {
			return err
		}

		*c = X509CertificateRequest(*certificate)
		return nil
	}

	return fmt.Errorf("missing cert block")
}

// --------------------------------------------
type X509PublicKey struct {
	Key any
}

func (c *X509PublicKey) String() string {
	res, err := c.MarshalJSON()
	if err != nil {
		return ""
	}

	certString := strings.ReplaceAll(string(res), "\"", "")

	return string(certString)
}

func (c *X509PublicKey) MarshalJSON() ([]byte, error) {
	data := []byte{}

	der, err := x509.MarshalPKIXPublicKey(c.Key)
	if err != nil {
		return nil, err
	}

	if c != nil {
		pemCert := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
		data = make([]byte, base64.StdEncoding.EncodedLen(len(pemCert)))
		base64.StdEncoding.Encode(data, pemCert)
		return json.Marshal(string(data))
	}

	return json.Marshal(data)
}

func (c *X509PublicKey) UnmarshalJSON(data []byte) error {
	var decoded []byte
	err := json.Unmarshal(data, &decoded)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(decoded)
	if block != nil {
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return err
		}

		*c = X509PublicKey{
			Key: key,
		}
		return nil
	}

	return fmt.Errorf("missing block")
}

// --------------------------------------------
type X509PrivateKey struct {
	Key any
}

func (c *X509PrivateKey) String() string {
	res, err := c.MarshalJSON()
	if err != nil {
		return ""
	}

	certString := strings.ReplaceAll(string(res), "\"", "")

	return string(certString)
}

func (c *X509PrivateKey) MarshalJSON() ([]byte, error) {
	data := []byte{}

	der, err := x509.MarshalPKIXPublicKey(c.Key)
	if err != nil {
		return nil, err
	}

	if c != nil {
		pemCert := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		data = make([]byte, base64.StdEncoding.EncodedLen(len(pemCert)))
		base64.StdEncoding.Encode(data, pemCert)
		return json.Marshal(string(data))
	}

	return json.Marshal(data)
}

func (c *X509PrivateKey) UnmarshalJSON(data []byte) error {
	var decoded []byte
	err := json.Unmarshal(data, &decoded)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(decoded)
	if block != nil {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return err
		}

		*c = X509PrivateKey{
			Key: key,
		}
		return nil
	}

	return fmt.Errorf("missing block")
}

// --------------------------------------------

func (X509Certificate) GormDataType() string {
	return "text"
}

func (c *X509Certificate) Scan(value interface{}) error {
	crtString, ok := value.(string)
	if !ok {
		return errors.New(fmt.Sprint("Failed to unmarshal JSONB value:", value))
	}

	crtBytes := []byte(fmt.Sprintf("\"%s\"", crtString))

	err := json.Unmarshal(crtBytes, &c)
	if err != nil {
		return err
	}

	return nil
}

// Value return json value, implement driver.Valuer interface
func (c X509Certificate) Value() (driver.Value, error) {
	return c.String(), nil
}

// --------------------------------------------
func (X509CertificateRequest) GormDataType() string {
	return "text"
}

func (c *X509CertificateRequest) Scan(value interface{}) error {
	crtString, ok := value.(string)
	if !ok {
		return errors.New(fmt.Sprint("Failed to unmarshal JSONB value:", value))
	}

	crtBytes := []byte(fmt.Sprintf("\"%s\"", crtString))

	err := json.Unmarshal(crtBytes, &c)
	if err != nil {
		return err
	}

	return nil
}

// Value return json value, implement driver.Valuer interface
func (c X509CertificateRequest) Value() (driver.Value, error) {
	return c.String(), nil
}
