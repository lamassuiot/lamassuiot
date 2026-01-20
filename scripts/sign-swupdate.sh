#!/bin/bash

# Lamassu IoT KMS SWUpdate Signature Script
# This script signs an SWUpdate sw-description file using the KMS service
# and creates a PKCS7/CMS signature that can be verified by the device.

# Arguments: Key ID, KMS URL, Algorithm, [Certificate Path]
KEY_ID="$1"
KMS_URL="$2"
ALGO="${3:-RSASSA_PSS_SHA_256}"
CERT_PATH="$4"

# Normalize algorithm name: replace dashes with underscores
ALGO=${ALGO//-/_}

if [ -z "$KEY_ID" ] || [ -z "$KMS_URL" ]; then
    echo "Usage: $0 <key_id> <kms_url> [algorithm] [certificate_path]"
    echo "Example: $0 e48a... https://localhost:8443/api/kms/v1 RSASSA_PSS_SHA_256 /path/to/cert.pem"
    echo ""
    echo "Arguments:"
    echo "  key_id           - KMS key identifier"
    echo "  kms_url          - KMS base URL"
    echo "  algorithm        - Signing algorithm (default: RSASSA_PSS_SHA_256)"
    echo "  certificate_path - Path to PEM certificate"
    echo ""
    echo "Certificate lookup order:"
    echo "  1. Fourth argument (certificate_path)"
    echo "  2. Environment variable: SWUPDATE_CERT_PATH"
    echo "  3. Default location: /etc/swupdate/certs/\${KEY_ID}.pem"
    echo ""
    echo "The certificate must be issued by a CA trusted by your devices."
    exit 1
fi

# Determine certificate path
# Priority: CLI argument > Environment variable > Default location based on key ID
if [ -n "$CERT_PATH" ]; then
    echo "Using certificate from command line argument: $CERT_PATH"
elif [ -n "$SWUPDATE_CERT_PATH" ]; then
    CERT_PATH="$SWUPDATE_CERT_PATH"
    echo "Using certificate from SWUPDATE_CERT_PATH environment variable: $CERT_PATH"
else
    # Default: look for certificate in standard location named after the key ID
    CERT_PATH="/etc/swupdate/certs/${KEY_ID}.pem"
    if [ ! -f "$CERT_PATH" ]; then
        # Try alternate location in user's home
        CERT_PATH="$HOME/.swupdate/certs/${KEY_ID}.pem"
    fi
    echo "Using certificate from default location: $CERT_PATH"
fi

# Validate certificate file exists
if [ ! -f "$CERT_PATH" ]; then
    echo "Error: Certificate file not found: $CERT_PATH"
    echo ""
    echo "Please provide a certificate using one of these methods:"
    echo "  1. Pass as 4th argument: $0 $KEY_ID $KMS_URL $ALGO /path/to/cert.pem"
    echo "  2. Set environment variable: export SWUPDATE_CERT_PATH=/path/to/cert.pem"
    echo "  3. Place certificate at: /etc/swupdate/certs/${KEY_ID}.pem"
    echo "     or: $HOME/.swupdate/certs/${KEY_ID}.pem"
    exit 1
fi

echo "Using certificate from: $CERT_PATH"

# Build JSON payload with required certificate
CERT_B64=$(base64 -w0 "$CERT_PATH")
JSON_DATA=$(python3 -c "import json, sys; print(json.dumps({'algorithm': sys.argv[1], 'message': sys.argv[2], 'message_type': 'raw', 'certificate': sys.argv[3]}))" "$ALGO" "$MESSAGE_B64" "$CERT_B64")

# Construct Endpoint URL
# Assuming KMS_URL is the base API path like https://localhost:8443/api/kms/v1
ENDPOINT="${KMS_URL}/keys/${KEY_ID}/sign"

echo "Sending request to: $ENDPOINT"

# Send request to KMS with Accept header to request PKCS7 format
RESPONSE=$(curl -k -s -X POST "$ENDPOINT" \
     -H "Content-Type: application/json" \
     -H "Accept: application/pkcs7-signature" \
     -d "$JSON_DATA")

# Check for curl errors
if [ $? -ne 0 ]; then
    echo "Error: curl command failed."
    exit 1
fi

# Check if response looks like an error (contains "err" field)
if echo "$RESPONSE" | grep -q '"err"'; then
    echo "Error from KMS:"
    echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
    exit 1
fi

# Response is base64-encoded PKCS7/CMS DER data
# Decode and write directly to sw-description.sig
echo -n "$RESPONSE" | base64 -d > "${SW_DESC}.sig"

if [ $? -eq 0 ] && [ -f "${SW_DESC}.sig" ]; then
    SIZE=$(stat -c%s "${SW_DESC}.sig")
    echo "Successfully created PKCS7/CMS signature: ${SW_DESC}.sig ($SIZE bytes)"
    
    # Display signature info using openssl
    if command -v openssl &> /dev/null; then
        echo ""
        echo "Signature information:"
        openssl pkcs7 -inform DER -in "${SW_DESC}.sig" -print_certs -noout 2>/dev/null || echo "(OpenSSL info not available)"
    fi
else
    echo "Error: Failed to write signature file."
    exit 1
fi
