package software

import (
	"context"

	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
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

	circlSign "cloudflare/circl/sign"
	"cloudflare/circl/sign/slhdsa"
	"crypto/mldsa"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
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

func (p *SoftwareCryptoEngine) GetEngineConfig() models.CryptoEngineInfo {
	return models.CryptoEngineInfo{
		Type:          models.Golang,
		SecurityLevel: models.SL1,
		Provider:      "Go standard library",
		Name:          "Software Crypto Engine",
		Metadata:      map[string]any{},
		SupportedKeyTypes: []models.SupportedKeyTypeInfo{
			{
				Type: models.KeyType(x509.RSA),
				Sizes: []int{
					1024,
					2048,
					3072,
					4096,
					7680,
					15360,
				},
			},
			{
				Type: models.KeyType(x509.ECDSA),
				Sizes: []int{
					224,
					256,
					384,
					521,
				},
			},
			{
				Type: models.KeyType(x509.MLDSA),
				Sizes: []int{
					44,
					65,
					87,
				},
			},
			{
				Type:  models.KeyType(x509.SLHDSA),
				Sizes: []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
			},
			{
				Type:  models.KeyType(x509.CompositeMLDSARSA),
				Sizes: []int{1, 2, 3, 4, 5, 6, 7, 8},
			},
			{
				Type: models.KeyType(x509.Ed25519),
				Sizes: []int{
					256,
				},
			},
		},
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

func (p *SoftwareCryptoEngine) CreateMLDSAPrivateKey(ctx context.Context, dimensions int) (string, crypto.Signer, error) {
	lFunc := p.logger.WithField("func", "ML-DSA")
	lFunc.Debugf("creating ML-DSA-%v key", dimensions)

	var params mldsa.Parameters
	switch dimensions {
	case 44:
		params = mldsa.MLDSA44()
	case 65:
		params = mldsa.MLDSA65()
	case 87:
		params = mldsa.MLDSA87()
	default:
		return "", nil, fmt.Errorf("invalid dimensions %v", dimensions)
	}

	key, err := mldsa.GenerateKey(params)
	if err != nil {
		lFunc.Errorf("could not create MLDSA key: %s", err)
		return "", nil, err
	}

	encDigest, err := p.EncodePKIXPublicKeyDigest(key.Public())
	if err != nil {
		lFunc.Errorf("could not encode public key digest: %s", err)
		return "", nil, err
	}

	return encDigest, key, nil
}

func (p *SoftwareCryptoEngine) CreateSLHDSAPrivateKey(ctx context.Context, paramSet int) (string, crypto.Signer, error) {
	lFunc := p.logger.WithField("func", "SLH-DSA")
	lFunc.Debugf("creating SLH-DSA paramSet=%v key", paramSet)

	_, key, err := slhdsa.GenerateKey(rand.Reader, slhdsa.ID(paramSet))
	if err != nil {
		lFunc.Errorf("could not create SLH-DSA key: %s", err)
		return "", nil, err
	}

	encDigest, err := p.EncodePKIXPublicKeyDigest(key.Public())
	if err != nil {
		lFunc.Errorf("could not encode public key digest: %s", err)
		return "", nil, err
	}

	return encDigest, key, nil
}

func (p *SoftwareCryptoEngine) ImportSLHDSAPrivateKey(key crypto.Signer) (string, crypto.Signer, error) {
	lFunc := p.logger.WithField("func", "SLH-DSA")
	lFunc.Debugf("importing SLH-DSA private key")

	encDigest, err := p.EncodePKIXPublicKeyDigest(key.Public())
	if err != nil {
		lFunc.Errorf("could not encode public key digest: %s", err)
		return "", nil, err
	}

	return encDigest, key, nil
}

func (p *SoftwareCryptoEngine) CreateCompositeMLDSARSAPrivateKey(ctx context.Context, variant int) (string, crypto.Signer, error) {
	lFunc := p.logger.WithField("func", "Composite-ML-DSA-RSA")
	lFunc.Debugf("creating Composite-ML-DSA-RSA variant=%v key", variant)

	if variant < 1 || variant > len(x509.CompositeAlgorithms) {
		return "", nil, fmt.Errorf("invalid composite variant %v (use 1-%d)", variant, len(x509.CompositeAlgorithms))
	}
	algo := x509.CompositeAlgorithms[variant-1]
	_, key, err := algo.GenerateCompositeKey(rand.Reader)
	if err != nil {
		lFunc.Errorf("could not create Composite-ML-DSA-RSA key: %s", err)
		return "", nil, err
	}

	encDigest, err := p.EncodePKIXPublicKeyDigest(key.Public())
	if err != nil {
		lFunc.Errorf("could not encode public key digest: %s", err)
		return "", nil, err
	}

	return encDigest, key, nil
}

func (p *SoftwareCryptoEngine) ImportCompositeMLDSARSAPrivateKey(key crypto.Signer) (string, crypto.Signer, error) {
	lFunc := p.logger.WithField("func", "Composite-ML-DSA-RSA")
	lFunc.Debugf("importing Composite-ML-DSA-RSA private key")

	encDigest, err := p.EncodePKIXPublicKeyDigest(key.Public())
	if err != nil {
		lFunc.Errorf("could not encode public key digest: %s", err)
		return "", nil, err
	}

	return encDigest, key, nil
}

func (p *SoftwareCryptoEngine) CreateEd25519PrivateKey() (string, crypto.Signer, error) {
	lFunc := p.logger.WithField("func", "Ed25519")
	lFunc.Debugf("creating Ed25519 key")

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		lFunc.Errorf("could not create Ed25519 key: %s", err)
		return "", nil, err
	}

	encDigest, err := p.EncodePKIXPublicKeyDigest(key.Public())
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

	pubkeyBytes, err := x509.MarshalPKIXPublicKey(key)
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

	// ParsePKCS8PrivateKey handles RSA, ECDSA, Ed25519, and stdlib-circl ML-DSA keys.
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
	case ed25519.PrivateKey:
		return key, nil
	case *mldsa.PrivateKey:
		return key, nil
	case circlSign.PrivateKey:
		return key, nil
	case *x509.CompositePrivateKey:
		return key, nil
	default:
		return nil, errors.New("unsupported key type")
	}
}
