# RFC 003: Azure Native Integration

| Status        | Proposed                                                                         |
| :------------ | :------------------------------------------------------------------------------- |
| **Author(s)** | Copilot                                                                          |
| **Created**   | 2026-01-15                                                                       |
| **Updated**   | 2026-01-15                                                                       |

## Summary

This RFC proposes the necessary adaptations and new engine implementations to allow Lamassu IoT to run natively on the Microsoft Azure cloud platform. This involves creating Azure-specific implementations for Crypto, Storage, Event Bus, and File System engines, as well as a new Connector for Azure IoT Hub.

## Motivation

To support deployments on Microsoft Azure that leverage managed services for scalability, security, and operational efficiency, rather than relying on self-hosted containers (e.g., RabbitMQ, MinIO) or cross-cloud dependencies.

## Design Details

### 1. Crypto Engine: Azure Key Vault (AKV)

*Ref: RFC-002*

- **Service**: Azure Key Vault (Standard or Managed HSM).
- **Library**: `github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys`.
- **Adaptation**:
    - Implementation of `core/pkg/engines/cryptoengines.CryptoEngine`.
    - Offloading key generation and signing to AKV.
    - Authentication via `azidentity.DefaultAzureCredential` (Managed Identity support).

### 2. Storage Engine: Azure Database for PostgreSQL (Flexible Server)

- **Service**: Azure Database for PostgreSQL.
- **Library**: `gorm.io/driver/postgres` (Standard) + `github.com/Azure/azure-sdk-for-go/sdk/azidentity`.
- **Adaptation**:
    - **Current**: The existing `engines/storage/postgres` uses standard connection strings.
    - **New Engine**: `engines/storage/azure-postgres`.
    - **Adaptation Logic**:
        - Instead of a static password in `config.yaml`, the engine will use `azidentity` to request an OAuth2 access token for the resource `https://oss-rdbms-aad.database.windows.net/.default`.
        - The token is used as the password in the PostgreSQL connection string.
        - This enables **Passwordless** connectivity using Managed Identities.
    - **Configuration**:
        ```go
        type AzurePostgresConfig struct {
            Host     string `mapstructure:"host"`
            User     string `mapstructure:"user"` // e.g., user@svr-name
            Database string `mapstructure:"database"`
            UseADDAuth bool `mapstructure:"use_aad_auth"`
        }
        ```

### 3. Event Bus Engine: Azure Service Bus

- **Service**: Azure Service Bus (Standard or Premium Tier).
- **Library**: `github.com/Azure/azure-sdk-for-go/sdk/messaging/azservicebus`.
- **Adaptation**:
    - **New Engine**: `engines/eventbus/azure`.
    - **Integration**: The implementation will act as a **Custom Watermill Adapter**, implementing `message.Publisher` and `message.Subscriber` interfaces from `github.com/ThreeDotsLabs/watermill`.
    - **Mapping**:
        - **Exchanges (AMQP)** -> **Topics** (Service Bus).
        - **Queues (AMQP)** -> **Subscriptions** (Service Bus).
    - **Implementation Details**:
        - `Publish(topic, data)`: Uses `Sender.SendMessage` to the specified Topic.
        - `Subscribe(topic, queueName)`: Creates a `Receiver` for the Topic's Subscription.
        - **Metadata**: CloudEvents attributes are mapped to Service Bus `ApplicationProperties`.
    - **Rationale**: Service Bus Topics provides the Pub/Sub model required by Lamassu's microservices architecture. Since there is no official Watermill adapter for Azure Service Bus, we will implement a custom one wrapping `azservicebus`.

### 4. File System Engine: Azure Blob Storage (Go CDK)

- **Service**: Azure Blob Storage.
- **Library**: `gocloud.dev/blob` (Generic) with `gocloud.dev/blob/azureblob` (Driver).
- **Adaptation**:
    - **Current**: The existing `engines/fs-storage` already uses `gocloud.dev/blob`.
    - **New Engine**: No new interface implementation is needed, just a new **Builder**.
    - **Implementation Details**:
        - Register a new `fs-storage` builder for `azure`.
        - Use `azureblob.OpenBucket` (or `blob.OpenBucket` with `azblob://` scheme).
        - **Authentication**: Use `azidentity.DefaultAzureCredential` passed to the `azureblob` driver options to ensure Passwordless/Managed Identity support.
    - **Bucket/Container**: Configured via the connection string or config struct (e.g., `azblob://my-container`).
    - **Outcome**: This allows us to reuse the exact same `fs-storage` logic used for `s3` and `localfs` without rewriting file operations.

### 5. Connector: Azure IoT Hub

- **Service**: Azure IoT Hub.
- **Library**: REST API wrapper (due to lack of official Go Data Plane SDK) or `github.com/amenzhinsky/iothub` (Community).
- **Adaptation**:
    - **New Module**: `connectors/azureiot/`.
    - **Functionality**:
        - Listens to `device.created` and `device.deleted` events from the Event Bus.
        - **Device Registry**: Calls Azure IoT Hub Registry APIs to create/delete device identities.
        - **Sync**: Ensures Lamassu device state matches Azure IoT Hub.
        - **Certificates**: Pushes generated certificates to IoT Hub if "Self-Signed" authentication is chosen, or manages the Thumbprint if "CA-Signed" is used.

## Configuration Strategy

To maintain consistency with the existing AWS implementation (see `shared/aws/config.go`), a new shared library `shared/azure` to store common Azure configuration structures.

### Shared Configuration (`shared/azure/config.go`)

This configuration will handle authentication strategies standardizing how all engines connect to Azure.

```go
package azure

import cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"

type AzureAuthenticationMethod string

const (
    // Default uses azidentity.NewDefaultAzureCredential()
    // Supports: Environment Vars, Workload Identity, Managed Identity, Azure CLI
    Default      AzureAuthenticationMethod = "default"
    
    // ClientSecret explicitly uses Client Secret credentials
    ClientSecret AzureAuthenticationMethod = "client_secret"
)

type AzureConfig struct {
    AuthenticationMethod AzureAuthenticationMethod `mapstructure:"auth_method"`
    
    // Identity - Optional if using "default" and Environment Variables
    TenantID       string           `mapstructure:"tenant_id"`
    ClientID       string           `mapstructure:"client_id"`
    ClientSecret   cconfig.Password `mapstructure:"client_secret"`
    
    // Topology - Used for resource discovery/management
    SubscriptionID string           `mapstructure:"subscription_id"`
    ResourceGroup  string           `mapstructure:"resource_group"`
    Location       string           `mapstructure:"location"`
}
```

### Engine Specific Configurations

Each engine will embed or reference the shared config, similar to `AWSSDKConfig`.

**1. Crypto Engine (Key Vault)**
```go
type AzureKVCryptoConfig struct {
    AzureConfig `mapstructure:",squash"`
    VaultURL    string `mapstructure:"vault_url"` // e.g. "https://my-vault.vault.azure.net/"
}
```

**2. Event Bus (Service Bus)**
```go
type AzureServiceBusConfig struct {
    AzureConfig `mapstructure:",squash"`
    Namespace   string `mapstructure:"namespace"` // e.g. "my-bus.servicebus.windows.net"
}
```

**3. Storage (Postgres via Managed Identity)**
```go
type AzurePostgresConfig struct {
    Host     string `mapstructure:"host"`
    User     string `mapstructure:"user"`
    Database string `mapstructure:"database"`
    // If true, ignores "password" and generates an access token using AzureConfig
    UseAADAuth bool        `mapstructure:"use_aad_auth"` 
    Azure      AzureConfig `mapstructure:"azure"`
}
```

**4. Blob Storage (FS)**
```go
type AzureBlobConfig struct {
    AzureConfig    `mapstructure:",squash"`
    StorageAccount string `mapstructure:"storage_account"` // e.g. "mystorage"
    Container      string `mapstructure:"container"`
    // Endpoint override for local emulators (Azurite)
    EndpointURL    string `mapstructure:"endpoint_url"` 
}
```

### Example YAML Configuration

```yaml
engines:
  crypto:
    type: "azure_kv"
    config:
      auth_method: "default"
      vault_url: "https://lamassu-kv.vault.azure.net/"

  eventbus:
    type: "azure_sb"
    config:
      auth_method: "client_secret"
      tenant_id: "00000000-0000-0000-0000-000000000000"
      client_id: "my-sp-id"
      client_secret: "my-sp-secret"
      namespace: "lamassu-bus.servicebus.windows.net"

  fs_storage:
    type: "azure_blob"
    config:
      auth_method: "default"
      storage_account: "lamassustorage"
      container: "certs"
```

## Migration Path

1.  **Phase 1**: Implement `azure` event bus and `azure-blob` keys.
2.  **Phase 2**: Implement `azure-kv` crypto engine.
3.  **Phase 3**: Implement `azureiot` connector.
4.  **Phase 4**: Full end-to-end integration test on an Azure Kubernetes Service (AKS) cluster with Workload Identity.
