#!/bin/bash

#Export .env variables
export $(grep -v '^#' .env | xargs)

#echo "1) Obtain the Root certificate"
if [ -d "./certificates" ]
then
    cd certificates
else
    mkdir certificates && cd certificates
fi
openssl s_client -connect $DOMAIN:443 2>/dev/null </dev/null |  sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > root-ca.pem

#echo "2) Create CA"
export AUTH_ADDR=auth.$DOMAIN
export TOKEN=$(curl -k --location --request POST "https://$AUTH_ADDR/auth/realms/lamassu/protocol/openid-connect/token" --header 'Content-Type: application/x-www-form-urlencoded' --data-urlencode 'grant_type=password' --data-urlencode 'client_id=frontend' --data-urlencode 'username=enroller' --data-urlencode 'password=enroller' | jq -r .access_token)

export CA_ADDR=$DOMAIN/api/ca
export CA_NAME=$(uuidgen)
export CREATE_CA_RESP=$(curl -k -s --location --request POST "https://$CA_ADDR/v1/pki/$CA_NAME" --header "Authorization: Bearer ${TOKEN}" --header 'Content-Type: application/json' --data-raw "{\"ca_ttl\": 262800, \"enroller_ttl\": 175200, \"subject\":{ \"common_name\": \"$CA_NAME\",\"country\": \"ES\",\"locality\": \"Arrasate\",\"organization\": \"LKS Next, S. Coop\",\"state\": \"Gipuzkoa\"},\"key_metadata\":{\"bits\": 4096,\"type\": \"RSA\"}}")
#echo $CREATE_CA_RESP

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

#echo "5) Enrolling with an existing private key"

export DMS_CRT=./dms.crt
export DMS_KEY=./dms.key
export DEVICE_ID=$(uuidgen)

openssl req -new -newkey rsa:2048 -nodes -keyout device.key -out device.csr -subj "/CN=$DEVICE_ID"
sed '/CERTIFICATE/d' device.csr > device_enroll.csr
curl https://$DOMAIN/api/devmanager/.well-known/est/$CA_NAME/simpleenroll --cert $DMS_CRT --key $DMS_KEY -s -o cert.p7 --cacert root-ca.pem  --data-binary @device_enroll.csr -H "Content-Type: application/pkcs10" 
openssl base64 -d -in cert.p7 | openssl pkcs7 -inform DER -outform PEM -print_certs -out cert.pem 
#echo "6) Reenrolling"

export DEVICE_CRT=cert.pem
export DEVICE_KEY=device.key

curl https://$DOMAIN/api/devmanager/.well-known/est/simplereenroll --cert $DEVICE_CRT --key $DEVICE_KEY -s -o newcert.p7 --cacert root-ca.pem --data-binary @device_enroll.csr -H "Content-Type: application/pkcs10" 
openssl base64 -d -in newcert.p7 | openssl pkcs7 -inform DER -outform PEM -print_certs -out $DEVICE_CRT 