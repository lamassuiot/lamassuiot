#!/bin/bash

#Export .env variables
export $(grep -v '^#' .env | xargs)

#echo "1)Obtain the Root certificate used by the server:"

openssl s_client -connect $DOMAIN:443  2>/dev/null </dev/null |  sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > root-ca.pem

#echo "2) Create CA"
export AUTH_ADDR=auth.$DOMAIN
export TOKEN=$(curl -k --location --request POST "https://$AUTH_ADDR/auth/realms/lamassu/protocol/openid-connect/token" --header 'Content-Type: application/x-www-form-urlencoded' --data-urlencode 'grant_type=password' --data-urlencode 'client_id=frontend' --data-urlencode 'username=enroller' --data-urlencode 'password=enroller' | jq -r .access_token)

export CA_ADDR=$DOMAIN/api/ca
export CA_NAME=$(uuidgen)
export CREATE_CA_RESP=$(curl -k -s --location --request POST "https://$CA_ADDR/v1/pki/$CA_NAME" --header "Authorization: Bearer ${TOKEN}" --header 'Content-Type: application/json' --data-raw "{\"ca_ttl\": 262800, \"enroller_ttl\": 175200, \"subject\":{ \"common_name\": \"$CA_NAME\",\"country\": \"ES\",\"locality\": \"Arrasate\",\"organization\": \"LKS Next, S. Coop\",\"state\": \"Gipuzkoa\"},\"key_metadata\":{\"bits\": 4096,\"type\": \"rsa\"}}")
echo $CREATE_CA_RESP | jq -r .certificate.pem_base64 | sed 's/\r/\n/g' | sed -Ez '$ s/\n+$//' | base64 -d > ca.crt

#echo "3) Create DMS"

export ENROLL_ADDR=$DOMAIN/api/dmsenroller
export TOKEN=$(curl -k --location --request POST "https://$AUTH_ADDR/auth/realms/lamassu/protocol/openid-connect/token" --header 'Content-Type: application/x-www-form-urlencoded' --data-urlencode 'grant_type=password' --data-urlencode 'client_id=frontend' --data-urlencode 'username=enroller' --data-urlencode 'password=enroller' | jq -r .access_token)
export DMS_NAME=$(uuidgen)
export DMS_REGISTER_RESPONSE=$(curl -k --location --request POST "https://$ENROLL_ADDR/v1/$DMS_NAME/form" --header "Authorization: Bearer ${TOKEN}" --header 'Content-Type: application/json' --data-raw "{\"name\": \"$DMS_NAME\", \"subject\":{\"common_name\": \"$DMS_NAME\",\"country\": \"ES\",\"locality\": \"\",\"organization\": \"\",\"organization_unit\": \"\",\"state\": \"\"},\"key_metadata\":{\"bits\": 3072,\"type\": \"RSA\"}}")
#echo $DMS_REGISTER_RESPONSE
echo $DMS_REGISTER_RESPONSE | jq -r .priv_key | sed 's/\r/\n/g' | sed -Ez '$ s/\n+$//' | base64 -d > dms.key
export DMS_ID=$(echo $DMS_REGISTER_RESPONSE | jq -r .dms.id)
export DMS_ENROLL_RESPONSE=$(curl -k --location --request PUT "https://$ENROLL_ADDR/v1/$DMS_ID" --header "Authorization: Bearer $TOKEN" --header 'Content-Type: application/json' --data-raw "{\"status\": \"APPROVED\",\"authorized_cas\": [\"$CA_NAME\"] }")
echo $DMS_ENROLL_RESPONSE | jq -r .crt | sed 's/\r/\n/g' | sed -Ez '$ s/\n+$//' | base64 -d > dms.crt

#echo "4) Enroll device"

export DMS_CRT=./dms.crt
export DMS_KEY=./dms.key
export DEVICE_ID=$(uuidgen)

openssl req -new -newkey rsa:2048 -nodes -keyout device.key -out device.csr -subj "/CN=$DEVICE_ID"
sed '1d' device.csr > device2.csr
mv  device2.csr device.csr
sed '$d' device.csr > device2.csr
mv  device2.csr device.csr

curl https://$DOMAIN/api/devmanager/.well-known/est/$CA_NAME/simpleenroll --cert $DMS_CRT --key $DMS_KEY -s -o cert.p7 --cacert root-ca.pem  --data-binary @device.csr -H "Content-Type: application/pkcs10" 
openssl base64 -d -in cert.p7 | openssl pkcs7 -inform DER -outform PEM -print_certs -out device.pem

#echo "5) Obtain the available CA certs:"

export CA_CERTIFICATE=ca.crt 
export DEVICE_CERTIFICATE=device.pem

openssl ocsp -issuer ca.crt -cert dev.crt -reqout - > ocsp-request-post.der

#echo "6) SCheck the status of the certificate"

curl --location --request POST "https://$DOMAIN/api/ocsp/" --header 'Content-Type: application/ocsp-request' --data-binary '@ocsp-request-post.der' > ocsp-response-post.der -k

#openssl ocsp -respin ocsp-response-post.der -VAfile lamassu-compose/tls-certificates/downstream/tls.crt -resp_text