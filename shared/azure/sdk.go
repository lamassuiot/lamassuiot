package azure

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

func GetAzureCredential(conf AzureSDKConfig) (azcore.TokenCredential, error) {
	if conf.TenantID == "" || conf.ClientID == "" {
		return nil, fmt.Errorf("tenant ID and client ID are required to authenticate")
	}
	switch conf.AzureAuthenticationMethod {
	case Secret:
		if conf.ClientSecret == "" {
			return nil, fmt.Errorf("client secret is required for secret authentication method")
		}
		return azidentity.NewClientSecretCredential(
			conf.TenantID,
			conf.ClientID,
			string(conf.ClientSecret),
			nil,
		)

	// Only RSA is supported for now by the azidentity package
	case Certificate:
		if conf.CertificatePath == "" || conf.KeyPath == "" {
			return nil, fmt.Errorf("certificate and key paths are required for certificate authentication method")
		}
		certPEM, err := os.ReadFile(conf.CertificatePath)
		if err != nil {
			return nil, fmt.Errorf("reading certificate file: %w", err)
		}

		keyPEM, err := os.ReadFile(conf.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("reading key file: %w", err)
		}

		tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate/key pair: %w", err)
		}

		leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("parsing leaf certificate: %w", err)
		}

		return azidentity.NewClientCertificateCredential(
			conf.TenantID,
			conf.ClientID,
			[]*x509.Certificate{leaf},
			tlsCert.PrivateKey,
			nil,
		)

	case Default:
		return azidentity.NewDefaultAzureCredential(nil)

	case Emulator:
		// floci-az (and Azurite) run in dev mode: all credentials are accepted
		// without validation. Return a no-op credential that satisfies the
		// azcore.TokenCredential interface without making any network calls.
		return &EmulatorCredential{}, nil

	default:
		return nil, fmt.Errorf("unsupported azure auth method: %q", conf.AzureAuthenticationMethod)
	}
}

// EmulatorCredential is a no-op TokenCredential for use with local Azure
// emulators (floci-az, Azurite) that accept any token in dev mode.
// It is exported so test packages can use it directly without going through
// GetAzureCredential.
type EmulatorCredential struct{}

func (e *EmulatorCredential) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "emulator"}, nil
}

// EmulatorAuthPolicy is a pipeline policy that injects a static bearer token.
// It is used alongside a nil credential (to bypass BearerTokenPolicy's HTTP
// check) so that local emulators requiring an Authorization header are satisfied.
type EmulatorAuthPolicy struct{}

func (p *EmulatorAuthPolicy) Do(req *policy.Request) (*http.Response, error) {
	req.Raw().Header.Set("Authorization", "Bearer emulator")
	return req.Next()
}
