package software

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestGetKeyRSAInPKCS1(t *testing.T) {
	engine := NewSoftwareCryptoEngine(logrus.StandardLogger().WithField("test", "TestGetKeyRSAInPKCS1"))

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("could not generate RSA key: %s", err)
	}

	pkcs1Der := x509.MarshalPKCS1PrivateKey(key)
	pemString := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: pkcs1Der})

	_, err = engine.ParsePrivateKey(pemString)
	assert.NoError(t, err)
}

func TestGetKeyRSAInPKCS8(t *testing.T) {
	engine := NewSoftwareCryptoEngine(logrus.StandardLogger().WithField("test", "TestGetKeyRSAInPKCS8"))

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("could not generate RSA key: %s", err)
	}

	pkcs8Der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("could not marshal RSA key: %s", err)
	}

	pemString := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Der})

	_, err = engine.ParsePrivateKey(pemString)
	assert.NoError(t, err)
}

func TestGetKeyECDSAInPKCS8(t *testing.T) {
	engine := NewSoftwareCryptoEngine(logrus.StandardLogger().WithField("test", "TestGetKeyECDSAInPKCS8"))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate ECDSA key: %s", err)
	}

	pkcs8Der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("could not marshal ECDSA key: %s", err)
	}

	pemString := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Der})

	_, err = engine.ParsePrivateKey(pemString)
	assert.NoError(t, err)
}

func TestGetKeyECDSAInSec1(t *testing.T) {
	engine := NewSoftwareCryptoEngine(logrus.StandardLogger().WithField("test", "TestGetKeyECDSAInSec1"))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate ECDSA key: %s", err)
	}

	pkcs8Der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("could not marshal ECDSA key: %s", err)
	}

	pemString := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: pkcs8Der})

	_, err = engine.ParsePrivateKey(pemString)
	assert.NoError(t, err)
}
