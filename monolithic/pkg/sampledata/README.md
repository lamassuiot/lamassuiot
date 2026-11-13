# Sample Data Generator

This package provides sample data generation for Lamassu IoT development and testing.

## Features

The sample data generator creates:

### Certificate Authorities

The CA service assigns the ID of every CA, so the sample CAs are identified by their common name, not by an ID.

1. **Sample Imported Root CA**
   - Uses the embedded ECDSA P-256 private key from `ecdsa_p256_key.pem`, imported into the KMS first
   - Self-signed certificate with 10-year validity
   - Created using the CreateCA API on that imported key

2. **Sample Generated Root CA**
   - Freshly generated ECDSA P-256 key pair
   - Self-signed certificate with 10-year validity
   - Created using the CreateCA API

Look them up by common name (`GET /v1/cas/cn/{common-name}` in the CA API), since their IDs differ on every run. The development monolithic starts with an empty database every time, so the sample data is always created from scratch.

### Certificates

From **each CA**, the following certificates are issued:

- **2 Device Certificates**: 
  - `device-cert-{ca-type}-001`
  - `device-cert-{ca-type}-002`
  - Each with corresponding DNS names

- **1 Server Certificate**: 
  - `server-cert-{ca-type}`
  - With multiple DNS SANs (e.g., `api.{ca-type}.example.com`, `www.{ca-type}.example.com`)

- **1 Client Certificate**: 
  - `client-cert-{ca-type}`
  - For client authentication scenarios

Where `{ca-type}` is either `imported` or `generated`.

### Other Resources

- **DMS** (Device Management System): `sample-dms-01`
- **10 Sample Devices**: With varied tags, icons, and metadata for testing device groups
- **Issuance Profiles**: 
  - CA profiles for the root CAs
  - Certificate profiles (device, server, client)

## Usage

The sample data is automatically populated when running the monolithic service in development mode:

```bash
go run ./monolithic/cmd/development/main.go
```

The `PopulateSampleData` function is called during service initialization and creates all sample resources using the SDK clients.

## Private Key

The ECDSA P-256 private key in `ecdsa_p256_key.pem` is embedded into the binary at compile time using Go's `//go:embed` directive. This allows the imported CA to be created consistently across different environments without requiring external key files.

**Note**: This key is for development/testing purposes only and should not be used in production environments.

## Certificate Details

All certificates use:
- **Key Type**: ECDSA P-256
- **Validity**: 1 year for leaf certificates, 10 years for CAs
- **Subject Organization**: LamassuIoT Sample
- **Subject Country**: ES (Spain)
- **Subject State**: Gipuzkoa
- **Subject Locality**: Arrasate
