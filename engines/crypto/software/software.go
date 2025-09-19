package software

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/sirupsen/logrus"
)

type SoftwareCryptoEngine struct {
	logger *logrus.Entry
}

func NewSoftwareCryptoEngine(logger *logrus.Entry) *SoftwareCryptoEngine {
	return &SoftwareCryptoEngine{
		logger: logger,
	}
}

// CreateRSAPrivateKey creates a RSA private key with the specified key size
func (p *SoftwareCryptoEngine) CreateRSAPrivateKey(keySize int) (string, *rsa.PrivateKey, error) {
	lFunc := p.logger.WithField("func", "RSA")
	lFunc.Debugf("creating RSA %d bit key", keySize)
	key, err := rsa.GenerateKey(rand.Reader, keySize)

	if err != nil {
		lFunc.Errorf("could not create RSA key: %s", err)
		return "", nil, err
	}

	encDigest, err := p.EncodePKIXPublicKeyDigest(&key.PublicKey)
	if err != nil {
		lFunc.Errorf("could not encode public key digest: %s", err)
		return "", nil, err
	}

	return encDigest, key, nil
}

func (p *SoftwareCryptoEngine) CreateECDSAPrivateKey(curve elliptic.Curve) (string, *ecdsa.PrivateKey, error) {
	lFunc := p.logger.WithField("func", "ECDSA")
	lFunc.Debugf("creating ECDSA %s key", curve.Params().Name)
	key, err := ecdsa.GenerateKey(curve, rand.Reader)

	if err != nil {
		lFunc.Errorf("could not create ECDSA key: %s", err)
		return "", nil, err
	}

	encDigest, err := p.EncodePKIXPublicKeyDigest(&key.PublicKey)
	if err != nil {
		lFunc.Errorf("could not encode public key digest: %s", err)
		return "", nil, err
	}

	return encDigest, key, nil
}

func (p *SoftwareCryptoEngine) MarshalAndEncodePKIXPrivateKey(key interface{}) (string, error) {
	p.logger.Debugf("marshaling and encoding PKIX private key")

	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		p.logger.Errorf("could not marshal PKIX private key: %s", err)
		return "", err
	}

	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})

	keyBase64 := base64.StdEncoding.EncodeToString([]byte(keyPem))
	p.logger.Debugf("private key (b64 encoded bytes): %s", keyBase64)

	return keyBase64, nil
}

func (p *SoftwareCryptoEngine) EncodePKIXPublicKeyDigest(key any) (string, error) {
	p.logger.Debugf("extracting and encoding public key")
	var pubkeyBytes []byte
	var err error

	pubkeyBytes, err = x509.MarshalPKIXPublicKey(key)
	if err != nil {
		p.logger.Errorf("could not marshal public key: %s", err)
		return "", err
	}

	hash := sha256.New()
	hash.Write(pubkeyBytes)
	digest := hash.Sum(nil)
	p.logger.Tracef("public key digest (bytes): %x", digest)

	hexDigest := hex.EncodeToString(digest)
	p.logger.Debugf("public key digest (hex encoded bytes): %s", hexDigest)

	return hexDigest, nil
}

func (p *SoftwareCryptoEngine) ParsePrivateKey(pemBytes []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no key found")
	}

	// First try to parse as PKCS8
	genericKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// If it fails, try to parse as PKCS1
		genericKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			// If it fails, try to parse as EC
			genericKey, err = x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
		}
	}

	switch key := genericKey.(type) {
	case *rsa.PrivateKey:
		return key, nil
	case *ecdsa.PrivateKey:
		return key, nil
	default:
		return nil, errors.New("unsupported key type")
	}
}
