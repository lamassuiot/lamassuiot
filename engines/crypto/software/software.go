package software

import (
	"context"
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
	"io"

	"github.com/lamassuiot/lamassuiot/sdk/v3"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
)

type LamassuEntropy struct {
	ctx context.Context
}

func NewLamassuEntropy(ctx context.Context) io.Reader {
	return &LamassuEntropy{ctx: ctx}
}

func (le *LamassuEntropy) Read(b []byte) (n int, err error) {
	_, span := otel.GetTracerProvider().Tracer("ca-svc").Start(le.ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName("Lamassu-Monolithic")))
	defer span.End()

	return rand.Read(b)
}

type SoftwareCryptoEngine struct {
	logger *logrus.Entry
}

func NewSoftwareCryptoEngine(logger *logrus.Entry) *SoftwareCryptoEngine {
	return &SoftwareCryptoEngine{
		logger: logger,
	}
}

// CreateRSAPrivateKey creates a RSA private key with the specified key size
func (p *SoftwareCryptoEngine) CreateRSAPrivateKey(ctx context.Context, keySize int) (string, *rsa.PrivateKey, error) {
	ctx, span := otel.GetTracerProvider().Tracer(fmt.Sprintf("RSA Key generation - %d", keySize)).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName("Lamassu-Monolithic")))
	defer span.End()

	entropy := NewLamassuEntropy(ctx)

	lFunc := p.logger.WithField("func", "RSA")
	lFunc.Debugf("creating RSA %d bit key", keySize)
	key, err := rsa.GenerateKey(entropy, keySize)

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

func (p *SoftwareCryptoEngine) CreateECDSAPrivateKey(ctx context.Context, curve elliptic.Curve) (string, *ecdsa.PrivateKey, error) {
	ctx, span := otel.GetTracerProvider().Tracer(fmt.Sprintf("ECDSA Key generation - %s", curve.Params().Name)).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName("Lamassu-Monolithic")))
	defer span.End()

	entropy := NewLamassuEntropy(ctx)

	lFunc := p.logger.WithField("func", "ECDSA")
	lFunc.Debugf("creating ECDSA %s key", curve.Params().Name)
	key, err := ecdsa.GenerateKey(curve, entropy)

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
