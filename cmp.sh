cat cli.sh
#!/bin/bash
date

################################################################################
# 🛠️  OpenSSL CMP Client Enrollment Script - Certificate Request Mode
################################################################################

# ------------------------------------------------------------------------------
# 🔧 Configuration Variables
# ------------------------------------------------------------------------------
CMP_SERVER="http://localhost:8080"
CMP_PATH="/api/dmsmanager/.well-known/cmp/p/testcmp"
# TRUSTED_CA_CERT="rollingstock.crt"
TRUSTED_CA_CERT="/home/ubuntu/dev/caf/caf-pki-local-agent/kit/client/root.pro.crt"
# MANUFACTURER_KEY="../agent.key"
# MANUFACTURER_CERT="../agent.crt"
MANUFACTURER_KEY="manuf.key"
MANUFACTURER_CERT="manuf.crt"

CLIENT_KEY="tmp/client.key"
CLIENT_KEY_PUB="tmp/client.pub"
CSR_FILE="tmp/client.csr"
CERT_OUT="tmp/client.crt"
CAS_OUT="tmp/client-capubs.crt"

IR_REQUEST_OUT="tmp/ir-request.der"

MANUFACTURING_CN=$(openssl x509 -in "$MANUFACTURER_CERT" -noout -subject | sed -n 's/.*CN=\([^,/]*\).*/\1/p')
MANUFACTURING_SN=$(openssl x509 -in "$MANUFACTURER_CERT" -noout -serial | sed -n 's/.*serial=\([^,/]*\).*/\1/p')

echo "🏭 Manufacturer Certificate CN: $MANUFACTURING_CN"
echo "🏭 Manufacturer Certificate SN: $MANUFACTURING_SN"

# CN_NAME=$(uuidgen)
CN_NAME=ikerlan-box-1

# ------------------------------------------------------------------------------
# 📦 Prepare Directories
# ------------------------------------------------------------------------------
mkdir -p tmp

# ------------------------------------------------------------------------------
# 🔐 Generate Private Key and CSR
# ------------------------------------------------------------------------------
# echo "🔑 Generating new key and CSR for CN=$CN_NAME (not using manufacturer key)..."
openssl genpkey -algorithm EC -out "$CLIENT_KEY" -pkeyopt ec_paramgen_curve:P-256
# openssl genpkey -algorithm RSA -out "$CLIENT_KEY" -pkeyopt rsa_keygen_bits:2048

# openssl ec -in "$CLIENT_KEY" -pubout -out "$CLIENT_KEY_PUB"
openssl ec -pubin -in  "$CLIENT_KEY_PUB" -outform DER -out "tmp/client.pub.der"
pubkeyderdigest=$(openssl dgst -sha256 "tmp/client.pub.der")
echo "📄 Public Key DER SHA256 Digest: $pubkeyderdigest"

if [ $? -ne 0 ]; then
    echo "❌ Failed to generate private key. Exiting."
    exit 1
fi

echo "📄 Generating CSR..."
openssl req -new -key "$CLIENT_KEY" -out "$CSR_FILE" -subj "/CN=$CN_NAME" -addext "subjectAltName=IP:192.168.1.10"

if [ $? -ne 0 ]; then
    echo "❌ Failed to generate CSR. Exiting."
    exit 1
fi

# ------------------------------------------------------------------------------
# 📡 Client: Send CMP Initialization Request (IR) authenticated with manufacturer key and cert
# ------------------------------------------------------------------------------

t0=$(date +%s)

echo "📤 Sending CMP Initialization Request from client to $CMP_SERVER$CMP_PATH..."
openssl cmp -server "$CMP_SERVER" \
    -verbosity 8 \
    -path "$CMP_PATH" \
    -cmd ir \
    -cert "$MANUFACTURER_CERT" -key "$MANUFACTURER_KEY" \
    -csr "$CSR_FILE" -newkey "$CLIENT_KEY" \
    -reqout "$IR_REQUEST_OUT" \
    -certout "$CERT_OUT" \
    -ignore_keyusage \
    -trusted "$TRUSTED_CA_CERT"

cmp_status=$?

t1=$(date +%s)
elapsed=$((t1 - t0))
echo "⏱️  CMP Initialization Request completed in $elapsed seconds."

if [ $cmp_status -ne 0 ]; then
    echo "❌ CMP Initialization Request failed. Check your CMP server and certificate settings."
    exit 1
fi

# ------------------------------------------------------------------------------
# ✅ Done
# ------------------------------------------------------------------------------
echo "🎉 Certificate enrollment completed. Output written to:"
echo "   Enrolled Certificate: $CERT_OUT"
echo "   CMP Request (IR): $IR_REQUEST_OUT"
echo "📜 Enrolled Certificate Contents:"
openssl x509 -in "$CERT_OUT" -text -noout

# Sleep 3 seconds
echo "⏳ Sleeping for 3 seconds to allow server processing..."
sleep 30
# Display the contents of the enrolled certificate

# ------------------------------------------------------------------------------
# 📡 Client: Send CMP Initialization Request (CR)
# ------------------------------------------------------------------------------

# Switch to use enrolled certificate for the next request

echo "📤 Sending CMP Certificate Request from client to $CMP_SERVER$CMP_PATH..."
openssl cmp -server "$CMP_SERVER" \
    -verbosity 8 \
    -path "$CMP_PATH" \
    -cmd cr \
    -cert "$CERT_OUT" \
    -key "$CLIENT_KEY" \
    -csr "$CSR_FILE" \
    -newkey "$CLIENT_KEY" \
    -reqout "$IR_REQUEST_OUT" \
    -certout "$CERT_OUT" \
    -cacertsout "$CAS_OUT" \
    -ignore_keyusage \
    -trusted "$TRUSTED_CA_CERT"
if [ $? -ne 0 ]; then
    echo "❌ CMP Certificate Request failed. Check your CMP server and certificate settings."
    exit 1
fi
# ------------------------------------------------------------------------------
# ✅ Done
# ------------------------------------------------------------------------------
echo "🎉 Certificate request completed. Output written to:"
echo "   Renewed Certificate: $CERT_OUT"
echo "   CA Certificates: $CAS_OUT"
echo "   CMP Request (CR): $IR_REQUEST_OUT"
echo "📜 Renewed Certificate Contents:"
openssl x509 -in "$CERT_OUT" -text -noout