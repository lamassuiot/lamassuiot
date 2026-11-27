#!/usr/bin/env bash
# Generates the CA fixtures of the 3.8 -> 4.0 upgrade test. Run it from this directory with OpenSSL 3 or later.
# The output is committed: the test never runs OpenSSL.
#
# In the 3.8 database:
#   a  OpenSSL CA, SKI as OpenSSL derives it (SHA-1 of the subjectPublicKey, RFC 5280 method 1)
#   b  OpenSSL CA with an arbitrary SKI: "patata" in ASCII
#   c  what CreateRootCA of Lamassu backend/v3.8.1 writes: SKI = AKI = the key digest (SHA-256 of the
#      DER SubjectPublicKeyInfo), CRL distribution point /crl/<digest>
# Imported on v4:
#   d  OpenSSL CA, SKI as OpenSSL derives it
#   e  OpenSSL CA with an arbitrary SKI: "patata2" in ASCII
set -euo pipefail

DAYS=36500
CA_EXT=(-addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign")

ec_key() { openssl ecparam -genkey -name "$1" -noout | openssl pkcs8 -topk8 -nocrypt -out "$2"; }
rsa_key() { openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1"; }
ca_cert() { # name cn extra-args...
	local name=$1 cn=$2
	shift 2
	openssl req -x509 -new -key "$name.key.pem" -subj "/CN=$cn" -days "$DAYS" "${CA_EXT[@]}" "$@" -out "$name.crt.pem"
}

ec_key prime256v1 a.key.pem
ca_cert a "Upgrade A OpenSSL" -addext "subjectKeyIdentifier=hash"

rsa_key b.key.pem
ca_cert b "Upgrade B Patata" -addext "subjectKeyIdentifier=706174617461"

ec_key prime256v1 c.key.pem
DC=$(openssl pkey -in c.key.pem -pubout -outform DER | sha256sum | cut -d' ' -f1)
ca_cert c "Upgrade C Lamassu 3.8" -addext "subjectKeyIdentifier=$DC" -addext "authorityKeyIdentifier=keyid:always" \
	-addext "crlDistributionPoints=URI:http://lamassu.example/crl/$DC"

ec_key secp384r1 d.key.pem
ca_cert d "Upgrade D OpenSSL" -addext "subjectKeyIdentifier=hash"

rsa_key e.key.pem
ca_cert e "Upgrade E Patata2" -addext "subjectKeyIdentifier=70617461746132"
