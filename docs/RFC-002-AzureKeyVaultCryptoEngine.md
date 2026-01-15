# RFC 002: Azure Key Vault Crypto Engine

| Status        | Proposed                                                   |
| :------------ | :--------------------------------------------------------- |
| **Author(s)** | Copilot                                                    |
| **Created**   | 2026-01-15                                                 |
| **Updated**   | 2026-01-15                                                 |

## Summary

This RFC proposes the implementation of a new `CryptoEngine` logic that integrates with **Azure Key Vault (AKV)**. This will allow the platform to offload cryptographic key storage and operations to Azure's managed HSM-backed service, providing enhanced security and compliance for keys used in CA and other services.

## Motivation

Currently, the project supports various crypto engines like Software, PKCS#11, and AWS KMS. Adding Azure Key Vault support is crucial for:
- **Cloud Agnosticness**: Enabling users running on Azure to use native key management services.
- **Security**: Leveraging AKV's FIPS 140-2 Level 2/3 validated HSMs.
- **Compliance**: Meeting regulatory requirements that demand keys to be managed in a hardware module.

## External Documentation Reference
- [Azure SDK for Go](https://context7.com/azure/azure-sdk-for-go)
- [Azure Key Vault Keys Client Module](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys)

## Design Details

### 1. New Module Structure

A new module will be created at `engines/crypto/azure/` following the existing pattern of other engines.

```text
engines/crypto/azure/
├── go.mod
├── azurekv.go       # Main implementation of CryptoEngine interface
├── azurekv_test.go  # Tests
├── config.go        # Configuration struct
└── signer.go        # Implementation of crypto.Signer
```

### 2. Configuration

The configuration will be part of the global configuration, loaded via mapstructure.

```go
type AzureKVConfig struct {
    VaultURL string `mapstructure:"vault_url"` // e.g., "https://my-vault.vault.azure.net/"
    // Auth is handled via azidentity.DefaultAzureCredential
    // which supports: Environment, Workload Identity, Managed Identity, Azure CLI
}
```

### 3. Dependencies

We will use the official Azure SDK for Go (New Generation):

- `github.com/Azure/azure-sdk-for-go/sdk/azidentity`: For authentication.
- `github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys`: For key management (Create, List, Delete, Get).
- `github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcrypto` (if available for operations) or `azkeys` clients for `Sign`/`Verify` operations.

### 4. Implementation Logic

The `AzureCryptoEngine` struct will implement `core/pkg/engines/cryptoengines.CryptoEngine`.

#### Initialization

The engine will initialize the `azkeys.Client` using the provided `VaultURL` and `DefaultAzureCredential`.

```go
cred, err := azidentity.NewDefaultAzureCredential(nil)
client, err := azkeys.NewClient(vaultURL, cred, nil)
```

#### Key Management (Create, List, Delete)

- **CreateRSAPrivateKey**: Calls `client.CreateKey` with `KeyType: RSA` and specified key size.
- **CreateECDSAPrivateKey**: Calls `client.CreateKey` with `KeyType: EC` and specified curve (P-256, P-384, P-521).
- **ListPrivateKeyIDs**: Uses `client.NewListKeysPager` to iterate over all keys in the vault, implementing pagination handling to return a full list of Key IDs (Names).
- **DeleteKey**: Calls `client.DeleteKey`. Note: We should check if `PurgeDeletedKey` is required depending on Soft-Delete settings, but `DeleteKey` is sufficient for logical deletion in the context of the interface.

#### `crypto.Signer` Implementation

The `GetPrivateKeyByID` method will return a custom struct `AzureKVSigner` that implements `crypto.Signer`.

```go
type AzureKVSigner struct {
    client   *azkeys.Client // Or crypto client
    keyID    string
    publicKey crypto.PublicKey
}
```

- **Public()**:
    - When `GetPrivateKeyByID` is called, we fetch the key details using `client.GetKey`.
    - The JSON Web Key (JWK) returned by Azure is converted to a Go `crypto.PublicKey` (RSA or ECDSA) and stored in the struct.
    - This method simply returns the cached public key.

- **Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts)**:
    - This method translates the Go `crypto.SignerOpts` (hash function, padding) into Azure Key Vault signing parameters.
    - It calls the remote Sign operation on Azure Key Vault.
    - **Note on Hashing**: Azure Key Vault expects the hash (digest) to be computed locally and sent to the vault, not the raw data.
    - **Algorithm Mapping**:
        - RSA: `RS256`, `RS384`, `RS512`, `PS256` etc. based on `opts`.
        - ECDSA: `ES256`, `ES384`, `ES512` based on curve size.

### 5. Integration

The new engine will be registered in `backend/pkg/assemblers/` or the relevant factories where `cryptoengines` are loaded.

## Security Considerations

- **Authentication**: Using `DefaultAzureCredential` allows secure, passwordless authentication in production (via Managed Identity) while supporting local development (via Azure CLI or Env Vars).
- **Network**: Ensure the Lamassu IoT instance has network access to the Azure Key Vault endpoint (443).
- **Permissions**: The identity used must have the following Key Vault permissions:
    - Key Management: `Get`, `List`, `Create`, `Delete`
    - Cryptographic Operations: `Sign`, `Verify`

## Open Questions

- **Versioning**: How to handle key rotation? The `GetPrivateKeyByID` currently takes a string ID. In Azure, keys have versions. We will likely default to the "latest" version or treat the Key Name as the ID.
- **Performance**: Every signature requires an HTTP round-trip to Azure. Latency impact on the CA signing process should be evaluated.

