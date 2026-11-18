# EST (Enrollment over Secure Transport) — usage in Lamassu IoT 🔧💡

A concise reference for using EST (RFC 7030) with Lamassu IoT, using OpenSSL and `curl`.

---

## Contents
- **Key endpoints & behavior**
- **Prerequisites**
- **Typical workflow**
- **Concrete examples** (generate key/CSR, fetch CA certs, enroll, extract/verify)
- **Troubleshooting & best practices**
- **One-shot script**
- **References**

---

## 1) Lamassu EST Implementation Details
Lamassu implements EST (RFC 7030) via the **DMS Manager** service.
- **URL Structure**: All endpoints typically require the **DMS ID** as an additional path segment (`aps`).
  - `HTTPS://<HOST>/.well-known/est/<DMS_ID>/simpleenroll`
- **Request Format**: The server expects the CSR body to be **Base64-encoded DER** (without PEM headers/footers).
- **Authentication**: Usage depends on DMS configuration:
  - **mTLS (Client Cert)**: Most common. Present a valid client certificate issued by a trusted CA (as configured in the DMS).
  - **NoAuth**: If enabled in DMS, no client cert is required.
  - **Webhook**: External authorization.
  - *Note: HTTP Basic Auth is not standardly supported.*

---

## 2) Key endpoints
- `GET /.well-known/est/<DMS_ID>/cacerts` — retrieve CA certificates (Base64-encoded PKCS#7).
- `POST /.well-known/est/<DMS_ID>/simpleenroll` — submit CSR to enroll a certificate.
- `POST /.well-known/est/<DMS_ID>/simplereenroll` — re-enroll using an existing certificate/key.
- `GET /.well-known/est/<DMS_ID>/csrattrs` — get CSR attributes.

---

## 3) Prerequisites
- OpenSSL
- `curl`
- Lamassu **DMS ID** (e.g., `dms-01`)
- Client Certificate (if DMS requires mTLS)
- Trust anchor (CA cert) to verify the server's TLS certificate

---

## 4) Typical workflow
1. Generate key & CSR (format as Base64).
2. `GET /cacerts` to get the trust anchor.
3. `POST` CSR to `/simpleenroll`.
4. Parse response (PKCS#7) to get the certificate.

---

## 5) Concrete examples

> Replace `est.example.com` with your server and `dms-01` with your DMS ID.

A) Generate key and CSR (Base64 encoded)

Lamassu expects the POST body to be the raw Base64 string of the DER CSR.

```bash
# 1. Generate Key & CSR
openssl genpkey -algorithm RSA -out device.key -pkeyopt rsa_keygen_bits:2048
openssl req -new -key device.key -out device.csr -subj "/CN=device-001/O=Acme"

# 2. Convert CSR to Base64 (remove newlines) for the payload
openssl req -in device.csr -outform DER | base64 -w 0 > device.b64
```

B) Fetch CA certs

```bash
# Fetch (response is Base64 PKCS#7)
curl -s -k "https://est.example.com/.well-known/est/dms-01/cacerts" -o cacerts.b64

# Convert to PEM
# 1. Decode Base64 -> DER
base64 -d cacerts.b64 > cacerts.p7b
# 2. Extract certs
openssl pkcs7 -inform DER -in cacerts.p7b -print_certs -out cacerts.pem

# Inspect
openssl x509 -in cacerts.pem -text -noout
```

C) Enroll (mTLS Auth)

```bash
curl -v -s -k \
  --cert client-auth.crt --key client-auth.key \
  -H "Content-Type: application/pkcs10" \
  --data-binary "@device.b64" \
  "https://est.example.com/.well-known/est/dms-01/simpleenroll" \
  -o enroll_resp.b64

# Process Response (Base64 PKCS#7 -> PEM)
base64 -d enroll_resp.b64 > enroll_resp.p7b
openssl pkcs7 -inform DER -in enroll_resp.p7b -print_certs -out device_cert.pem

# Verify
openssl verify -CAfile cacerts.pem device_cert.pem
```

D) Enroll (No Auth / No Client Cert)
*Only if DMS allows NoAuth*

```bash
curl -v -s -k \
  -H "Content-Type: application/pkcs10" \
  --data-binary "@device.b64" \
  "https://est.example.com/.well-known/est/dms-01/simpleenroll" \
  -o enroll_resp.b64
```

E) Re-enroll
Authenticates with the *current* device certificate.

```bash
# Generate new CSR -> Base64
openssl req -new -key device.key -out device_re.csr -subj "/CN=device-001/O=Acme"
openssl req -in device_re.csr -outform DER | base64 -w 0 > device_re.b64

# Request re-enrollment using current cert for auth
curl -v -s -k \
  --cert device_cert.pem --key device.key \
  -H "Content-Type: application/pkcs10" \
  --data-binary "@device_re.b64" \
  "https://est.example.com/.well-known/est/dms-01/simplereenroll" \
  -o reenroll_resp.b64

# Process response
base64 -d reenroll_resp.b64 | openssl pkcs7 -inform DER -print_certs -out device_re_cert.pem
```

F) Server-Side Key Generation
Requests the server to generate the private key. Returns a `multipart/mixed` response containing the Key and Certificate.

```bash
# Request (using existing cert for auth)
curl -v -s -k \
  --cert device_cert.pem --key device.key \
  -H "Content-Type: application/pkcs10" \
  --data-binary "@device.b64" \
  "https://est.example.com/.well-known/est/dms-01/serverkeygen" \
  -o response.mime

# The response contains two parts separated by boundary "--estServerLamassuBoundary":
# 1. Private Key (application/pkcs8) -> Base64 encoded
# 2. Certificate (application/pkcs7-mime) -> Base64 encoded
```

---

## 6) Troubleshooting & best practices ✅⚠️
- **Status 400 Bad Request**: Often due to malformed Body. Ensure you are sending **Base64-encoded DER**, not PEM, not raw binary. Use `base64 -w 0` to avoid newlines.
- **Status 404 Not Found**: Check if `<DMS_ID>` is correct and the DMS exists.
- **Status 401/403**: Check Client Certificate validity. The DMS Configuration (`ValidationCAs`) must trust the issuer of your client cert.
- **Server Responses**: Lamassu returns `application/pkcs7-mime` with `Content-Transfer-Encoding: base64`. The body is Base64 text. You must decode it (`base64 -d`) before passing to `openssl pkcs7 -inform DER`.

---

## 7) Example "one-shot" script (mTLS)

```bash
#!/usr/bin/env bash
set -euo pipefail

EST_HOST="https://est.example.com"
DMS_ID="dms-01"
# Auth creds (bootstrap cert)
AUTH_CERT="bootstrap.crt"
AUTH_KEY="bootstrap.key"

# Output files
KEY="device.key"
CSR_DER="device.csr.der"
CSR_B64="device.csr.b64"
CA_B64="cacerts.b64"
CA_PEM="cacerts.pem"
RESP_B64="resp.b64"
DEV_PEM="device_final.pem"

echo "1. Generating Key..."
openssl genpkey -algorithm RSA -out $KEY -pkeyopt rsa_keygen_bits:2048
openssl req -new -key $KEY -outform DER -out $CSR_DER -subj "/CN=device-XX/O=Lamassu"
base64 -w 0 $CSR_DER > $CSR_B64

echo "2. Fetching CA Params..."
curl -s -k "$EST_HOST/.well-known/est/$DMS_ID/cacerts" -o $CA_B64
base64 -d $CA_B64 | openssl pkcs7 -inform DER -print_certs -out $CA_PEM

echo "3. Enrolling..."
curl -s -k \
  --cert $AUTH_CERT --key $AUTH_KEY \
  -H "Content-Type: application/pkcs10" \
  --data-binary "@$CSR_B64" \
  "$EST_HOST/.well-known/est/$DMS_ID/simpleenroll" \
  -o $RESP_B64

echo "4. Processing Response..."
if [ -s "$RESP_B64" ]; then
    base64 -d $RESP_B64 | openssl pkcs7 -inform DER -print_certs -out $DEV_PEM
    openssl verify -CAfile $CA_PEM $DEV_PEM && echo "SUCCESS: Certificate Enrolled & Verified"
else
    echo "ERROR: Empty response"
    exit 1
fi
```

## References
- RFC 7030
