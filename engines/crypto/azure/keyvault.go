package azure

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/google/uuid"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	software "github.com/lamassuiot/lamassuiot/engines/crypto/software/v3"
	lazure "github.com/lamassuiot/lamassuiot/shared/azure/v3"
	"github.com/sirupsen/logrus"
)

var lAzureKV *logrus.Entry

// lamassuIDTag is the Key Vault tag key used to store the Lamassu key ID
// (hex-encoded SHA256 of the PKIX public key). Key Vault key names are UUIDs
// because the public key hash is only known after creation; this tag bridges
// the internal UUID name to the external Lamassu ID.
const lamassuIDTag = "x-lamassu-id"

type AzureKeyVaultCryptoEngine struct {
	softCryptoEngine *software.SoftwareCryptoEngine
	config           models.CryptoEngineInfo
	keyVaultCli      *azkeys.Client
	logger           *logrus.Entry
}

// emulatorAuthPolicy injects a static bearer token on every request.
// floci-az and Azurite in dev mode require an Authorization header but accept
// any token value, so this satisfies the requirement without a real credential.

func NewAzureKeyVaultEngine(logger *logrus.Entry, vaultURL string, credential azcore.TokenCredential, allowHTTP bool, metadata map[string]any) (cryptoengines.CryptoEngine, error) {
	lAzureKV = logger.WithField("subsystem-provider", "Azure Key Vault Client")

	clientOpts := &azkeys.ClientOptions{}

	// KeyVaultChallengePolicy passes the credential straight to BearerTokenPolicy,
	// which rejects plain HTTP regardless of client options. When allowHTTP is set:
	//   - pass nil credential so BearerTokenPolicy skips its HTTP check entirely
	//   - inject a PerCallPolicy that adds "Authorization: Bearer emulator" so the
	//     emulator (which requires the header but accepts any token) responds with 200
	effectiveCred := credential
	if allowHTTP {
		effectiveCred = nil
		clientOpts.ClientOptions = azcore.ClientOptions{
			PerCallPolicies: []policy.Policy{&lazure.EmulatorAuthPolicy{}},
		}
	}

	client, err := azkeys.NewClient(vaultURL, effectiveCred, clientOpts)
	if err != nil {
		return nil, fmt.Errorf("creating Key Vault client: %w", err)
	}

	return &AzureKeyVaultCryptoEngine{
		logger:           lAzureKV,
		keyVaultCli:      client,
		softCryptoEngine: software.NewSoftwareCryptoEngine(lAzureKV),
		config: models.CryptoEngineInfo{
			Type:          models.AzureKeyVault,
			SecurityLevel: models.SL1,
			Provider:      "Microsoft Azure",
			Name:          "Key Vault",
			Metadata:      metadata,
			SupportedKeyTypes: []models.SupportedKeyTypeInfo{
				{
					Type: models.KeyType(x509.RSA),
					Sizes: []int{
						2048,
						3072,
						4096,
					},
				},
				{
					Type: models.KeyType(x509.ECDSA),
					Sizes: []int{
						256,
						384,
						521,
					},
				},
			},
		},
	}, nil
}

func (p *AzureKeyVaultCryptoEngine) GetEngineConfig() models.CryptoEngineInfo {
	return p.config
}

func (p *AzureKeyVaultCryptoEngine) ListPrivateKeyIDs() ([]string, error) {
	var keyIDs []string
	pager := p.keyVaultCli.NewListKeyPropertiesPager(nil)
	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			return nil, fmt.Errorf("listing keys: %w", err)
		}
		for _, kp := range page.Value {
			if id, ok := kp.Tags[lamassuIDTag]; ok && id != nil {
				keyIDs = append(keyIDs, *id)
			}
		}
	}
	return keyIDs, nil
}

// findKeyNameByLamassuID iterates all Key Vault keys and returns the internal
// UUID name for the key whose lamassuIDTag matches the given Lamassu key ID.
func (p *AzureKeyVaultCryptoEngine) findKeyNameByLamassuID(ctx context.Context, keyID string) (string, error) {
	pager := p.keyVaultCli.NewListKeyPropertiesPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return "", fmt.Errorf("listing keys: %w", err)
		}
		for _, kp := range page.Value {
			if id, ok := kp.Tags[lamassuIDTag]; ok && id != nil && *id == keyID {
				return kp.KID.Name(), nil
			}
		}
	}
	return "", fmt.Errorf("key with lamassu ID %q not found in Key Vault", keyID)
}

func (p *AzureKeyVaultCryptoEngine) GetPrivateKeyByID(keyID string) (crypto.Signer, error) {
	lAzureKV.Debugf("Getting the private key with Lamassu ID: %s", keyID)
	keyName, err := p.findKeyNameByLamassuID(context.Background(), keyID)
	if err != nil {
		return nil, err
	}
	return newKeyVaultSignerWrapper(p.keyVaultCli, keyName)
}

func (p *AzureKeyVaultCryptoEngine) CreateRSAPrivateKey(ctx context.Context, keySize int) (string, crypto.Signer, error) {
	lAzureKV.Debugf("Creating RSA key with size %d", keySize)

	switch keySize {
	case 2048, 3072, 4096:
	default:
		return "", nil, fmt.Errorf("RSA key size %d not supported by Azure Key Vault", keySize)
	}

	kty := azkeys.KeyTypeRSA
	kSize := int32(keySize)
	ops := allowedKeyOps()
	resp, err := p.keyVaultCli.CreateKey(ctx, uuid.NewString(), azkeys.CreateKeyParameters{
		Kty:     &kty,
		KeySize: &kSize,
		KeyOps:  ops,
	}, nil)
	if err != nil {
		return "", nil, fmt.Errorf("creating RSA key in Key Vault: %w", err)
	}

	return p.registerCreatedKey(ctx, resp.Key.KID)
}

func (p *AzureKeyVaultCryptoEngine) CreateECDSAPrivateKey(ctx context.Context, curve elliptic.Curve) (string, crypto.Signer, error) {
	lAzureKV.Debugf("Creating ECDSA key with curve %s", curve.Params().Name)

	crv, err := ecCurveToAzure(curve)
	if err != nil {
		return "", nil, err
	}

	kty := azkeys.KeyTypeEC
	ops := allowedKeyOps()
	resp, err := p.keyVaultCli.CreateKey(ctx, uuid.NewString(), azkeys.CreateKeyParameters{
		Kty:    &kty,
		Curve:  &crv,
		KeyOps: ops,
	}, nil)
	if err != nil {
		return "", nil, fmt.Errorf("creating ECDSA key in Key Vault: %w", err)
	}

	return p.registerCreatedKey(ctx, resp.Key.KID)
}

func (p *AzureKeyVaultCryptoEngine) ImportRSAPrivateKey(key *rsa.PrivateKey) (string, crypto.Signer, error) {
	key.Precompute()

	keyID, err := p.softCryptoEngine.EncodePKIXPublicKeyDigest(&key.PublicKey)
	if err != nil {
		return "", nil, fmt.Errorf("encoding public key digest: %w", err)
	}

	kty := azkeys.KeyTypeRSA
	jwk := &azkeys.JSONWebKey{
		Kty: &kty,
		N:   key.PublicKey.N.Bytes(),
		E:   big.NewInt(int64(key.PublicKey.E)).Bytes(),
		D:   key.D.Bytes(),
		P:   key.Primes[0].Bytes(),
		Q:   key.Primes[1].Bytes(),
		DP:  key.Precomputed.Dp.Bytes(),
		DQ:  key.Precomputed.Dq.Bytes(),
		QI:  key.Precomputed.Qinv.Bytes(),
	}

	_, err = p.keyVaultCli.ImportKey(context.Background(), keyID, azkeys.ImportKeyParameters{Key: jwk}, nil)
	if err != nil {
		return "", nil, fmt.Errorf("importing RSA key into Key Vault: %w", err)
	}

	signer, err := newKeyVaultSignerWrapper(p.keyVaultCli, keyID)
	if err != nil {
		return "", nil, err
	}

	return keyID, signer, nil
}

func (p *AzureKeyVaultCryptoEngine) ImportECDSAPrivateKey(key *ecdsa.PrivateKey) (string, crypto.Signer, error) {
	keyID, err := p.softCryptoEngine.EncodePKIXPublicKeyDigest(&key.PublicKey)
	if err != nil {
		return "", nil, fmt.Errorf("encoding public key digest: %w", err)
	}

	crv, err := ecCurveToAzure(key.Curve)
	if err != nil {
		return "", nil, err
	}

	byteLen := (key.Curve.Params().BitSize + 7) / 8
	kty := azkeys.KeyTypeEC
	jwk := &azkeys.JSONWebKey{
		Kty: &kty,
		Crv: &crv,
		X:   padLeft(key.PublicKey.X.Bytes(), byteLen),
		Y:   padLeft(key.PublicKey.Y.Bytes(), byteLen),
		D:   padLeft(key.D.Bytes(), byteLen),
	}

	_, err = p.keyVaultCli.ImportKey(context.Background(), keyID, azkeys.ImportKeyParameters{Key: jwk}, nil)
	if err != nil {
		return "", nil, fmt.Errorf("importing ECDSA key into Key Vault: %w", err)
	}

	signer, err := newKeyVaultSignerWrapper(p.keyVaultCli, keyID)
	if err != nil {
		return "", nil, err
	}

	return keyID, signer, nil
}

// RenameKey is not supported by Azure Key Vault — key names are immutable once created.
func (p *AzureKeyVaultCryptoEngine) RenameKey(oldID, newID string) error {
	return fmt.Errorf("renaming keys is not supported by Azure Key Vault: key names are immutable (old=%s, new=%s)", oldID, newID)
}

func (p *AzureKeyVaultCryptoEngine) DeleteKey(keyID string) error {
	keyName, err := p.findKeyNameByLamassuID(context.Background(), keyID)
	if err != nil {
		return err
	}
	_, err = p.keyVaultCli.DeleteKey(context.Background(), keyName, nil)
	if err != nil {
		return fmt.Errorf("deleting key %s from Key Vault: %w", keyName, err)
	}
	return nil
}

// registerCreatedKey builds a signer for the newly created key, computes its
// Lamassu ID, and tags the Key Vault key so it can be looked up later.
func (p *AzureKeyVaultCryptoEngine) registerCreatedKey(ctx context.Context, kid *azkeys.ID) (string, crypto.Signer, error) {
	keyName := kid.Name()
	keyVersion := kid.Version()

	signer, err := newKeyVaultSignerWrapper(p.keyVaultCli, keyName)
	if err != nil {
		return "", nil, err
	}

	keyID, err := p.softCryptoEngine.EncodePKIXPublicKeyDigest(signer.Public())
	if err != nil {
		return "", nil, fmt.Errorf("encoding public key digest: %w", err)
	}

	_, err = p.keyVaultCli.UpdateKey(ctx, keyName, keyVersion, azkeys.UpdateKeyParameters{
		Tags: map[string]*string{lamassuIDTag: &keyID},
	}, nil)
	if err != nil {
		lAzureKV.Warnf("could not tag Key Vault key %s with lamassu ID: %s", keyName, err)
	}

	return keyID, signer, nil
}

// ---- helpers ----

func allowedKeyOps() []*azkeys.KeyOperation {
	sign := azkeys.KeyOperationSign
	verify := azkeys.KeyOperationVerify
	return []*azkeys.KeyOperation{&sign, &verify}
}

func ecCurveToAzure(curve elliptic.Curve) (azkeys.CurveName, error) {
	switch curve {
	case elliptic.P256():
		return azkeys.CurveNameP256, nil
	case elliptic.P384():
		return azkeys.CurveNameP384, nil
	case elliptic.P521():
		return azkeys.CurveNameP521, nil
	default:
		return "", fmt.Errorf("unsupported EC curve %s for Azure Key Vault", curve.Params().Name)
	}
}

func padLeft(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}

func jwkToPublicKey(jwk *azkeys.JSONWebKey) (crypto.PublicKey, error) {
	if jwk == nil || jwk.Kty == nil {
		return nil, fmt.Errorf("nil or incomplete JWK")
	}
	switch *jwk.Kty {
	case azkeys.KeyTypeRSA, azkeys.KeyTypeRSAHSM:
		n := new(big.Int).SetBytes(jwk.N)
		e := new(big.Int).SetBytes(jwk.E)
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case azkeys.KeyTypeEC, azkeys.KeyTypeECHSM:
		curve, err := azureCurveToEC(jwk.Crv)
		if err != nil {
			return nil, err
		}
		x := new(big.Int).SetBytes(jwk.X)
		y := new(big.Int).SetBytes(jwk.Y)
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	default:
		return nil, fmt.Errorf("unsupported JWK key type: %s", *jwk.Kty)
	}
}

func azureCurveToEC(crv *azkeys.CurveName) (elliptic.Curve, error) {
	if crv == nil {
		return nil, fmt.Errorf("nil curve name")
	}
	switch *crv {
	case azkeys.CurveNameP256:
		return elliptic.P256(), nil
	case azkeys.CurveNameP384:
		return elliptic.P384(), nil
	case azkeys.CurveNameP521:
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported Azure Key Vault curve: %s", *crv)
	}
}

// ---- signer wrapper ----

type keyVaultSignerWrapper struct {
	keyName string
	version string
	client  *azkeys.Client
	pubKey  crypto.PublicKey
}

func newKeyVaultSignerWrapper(client *azkeys.Client, keyName string) (crypto.Signer, error) {
	resp, err := client.GetKey(context.Background(), keyName, "", nil)
	if err != nil {
		return nil, fmt.Errorf("fetching key %s from Key Vault: %w", keyName, err)
	}

	pubKey, err := jwkToPublicKey(resp.Key)
	if err != nil {
		return nil, fmt.Errorf("parsing public key for %s: %w", keyName, err)
	}

	version := ""
	if resp.Key.KID != nil {
		version = resp.Key.KID.Version()
	}

	return &keyVaultSignerWrapper{
		keyName: keyName,
		version: version,
		client:  client,
		pubKey:  pubKey,
	}, nil
}

func (k *keyVaultSignerWrapper) Public() crypto.PublicKey {
	return k.pubKey
}

func (k *keyVaultSignerWrapper) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	alg, err := getKVSigningAlgorithm(k.pubKey, opts)
	if err != nil {
		return nil, err
	}

	resp, err := k.client.Sign(context.Background(), k.keyName, k.version, azkeys.SignParameters{
		Algorithm: &alg,
		Value:     digest,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("signing with Key Vault key %s: %w", k.keyName, err)
	}

	// Azure Key Vault returns ECDSA signatures in IEEE P1363 format (r||s).
	// Go's crypto.Signer contract expects DER/ASN.1 encoding for ECDSA.
	if _, isEC := k.pubKey.(*ecdsa.PublicKey); isEC {
		return p1363ToDER(resp.Result)
	}

	return resp.Result, nil
}

func getKVSigningAlgorithm(key crypto.PublicKey, opts crypto.SignerOpts) (azkeys.SignatureAlgorithm, error) {
	switch key.(type) {
	case *rsa.PublicKey:
		_, isPSS := opts.(*rsa.PSSOptions)
		switch opts.HashFunc() {
		case crypto.SHA256:
			if isPSS {
				return azkeys.SignatureAlgorithmPS256, nil
			}
			return azkeys.SignatureAlgorithmRS256, nil
		case crypto.SHA384:
			if isPSS {
				return azkeys.SignatureAlgorithmPS384, nil
			}
			return azkeys.SignatureAlgorithmRS384, nil
		case crypto.SHA512:
			if isPSS {
				return azkeys.SignatureAlgorithmPS512, nil
			}
			return azkeys.SignatureAlgorithmRS512, nil
		default:
			return "", fmt.Errorf("unsupported hash function %v for RSA signing", opts.HashFunc())
		}
	case *ecdsa.PublicKey:
		switch opts.HashFunc() {
		case crypto.SHA256:
			return azkeys.SignatureAlgorithmES256, nil
		case crypto.SHA384:
			return azkeys.SignatureAlgorithmES384, nil
		case crypto.SHA512:
			return azkeys.SignatureAlgorithmES512, nil
		default:
			return "", fmt.Errorf("unsupported hash function %v for ECDSA signing", opts.HashFunc())
		}
	default:
		return "", fmt.Errorf("unsupported key type %T", key)
	}
}

// p1363ToDER converts an IEEE P1363 ECDSA signature (r||s) to DER/ASN.1 format.
func p1363ToDER(sig []byte) ([]byte, error) {
	if len(sig) == 0 || len(sig)%2 != 0 {
		return nil, fmt.Errorf("invalid P1363 ECDSA signature length %d", len(sig))
	}
	half := len(sig) / 2
	r := new(big.Int).SetBytes(sig[:half])
	s := new(big.Int).SetBytes(sig[half:])
	type ecdsaSig struct{ R, S *big.Int }
	return asn1.Marshal(ecdsaSig{R: r, S: s})
}
