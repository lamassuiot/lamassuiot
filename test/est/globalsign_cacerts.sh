#!/bin/bash

#Export .env variables
export $(grep -v '^#' .env | xargs)

#echo "1) Install GlobalSign Est Client"
go get github.com/globalsign/est
go mod vendor
go install github.com/globalsign/est/cmd/estclient@latest


#echo "2) Obtain the Root certificate"
if [ -d "./certificates" ]
then
    cd certificates
else
    mkdir certificates && cd certificates
fi

openssl s_client -connect $DOMAIN:443 2>/dev/null </dev/null |  sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > root-ca.pem

#echo "3) Create CA"
export AUTH_ADDR=auth.$DOMAIN
export TOKEN=$(curl -k --location --request POST "https://$AUTH_ADDR/auth/realms/lamassu/protocol/openid-connect/token" --header 'Content-Type: application/x-www-form-urlencoded' --data-urlencode 'grant_type=password' --data-urlencode 'client_id=frontend' --data-urlencode 'username=enroller' --data-urlencode 'password=enroller' | jq -r .access_token)

export CA_ADDR=$DOMAIN/api/ca
export CA_NAME=$(uuidgen)
export CREATE_CA_RESP=$(curl -k -s --location --request POST "https://$CA_ADDR/v1/pki/$CA_NAME" --header "Authorization: Bearer ${TOKEN}" --header 'Content-Type: application/json' --data-raw "{\"ca_ttl\": 262800, \"enroller_ttl\": 175200, \"subject\":{ \"common_name\": \"$CA_NAME\",\"country\": \"ES\",\"locality\": \"Arrasate\",\"organization\": \"LKS Next, S. Coop\",\"state\": \"Gipuzkoa\"},\"key_metadata\":{\"bits\": 4096,\"type\": \"RSA\"}}")
#echo $CREATE_CA_RESP

#echo "4) Create DMS"
export ENROLL_ADDR=$DOMAIN/api/dmsenroller
export TOKEN=$(curl -k --location --request POST "https://$AUTH_ADDR/auth/realms/lamassu/protocol/openid-connect/token" --header 'Content-Type: application/x-www-form-urlencoded' --data-urlencode 'grant_type=password' --data-urlencode 'client_id=frontend' --data-urlencode 'username=enroller' --data-urlencode 'password=enroller' | jq -r .access_token)
export DMS_NAME=$(uuidgen)
export DMS_REGISTER_RESPONSE=$(curl -k --location --request POST "https://$ENROLL_ADDR/v1/$DMS_NAME/form" --header "Authorization: Bearer ${TOKEN}" --header 'Content-Type: application/json' --data-raw "{\"name\": \"$DMS_NAME\", \"subject\":{\"common_name\": \"$DMS_NAME\",\"country\": \"ES\",\"locality\": \"\",\"organization\": \"\",\"organization_unit\": \"\",\"state\": \"\"},\"key_metadata\":{\"bits\": 3072,\"type\": \"RSA\"}}")
#echo $DMS_REGISTER_RESPONSE
echo $DMS_REGISTER_RESPONSE | jq -r .priv_key | sed 's/\r/\n/g' | sed -Ez '$ s/\n+$//' | base64 -d > dms.key
export DMS_ID=$(echo $DMS_REGISTER_RESPONSE | jq -r .dms.id)
export DMS_ENROLL_RESPONSE=$(curl -k --location --request PUT "https://$ENROLL_ADDR/v1/$DMS_ID" --header "Authorization: Bearer $TOKEN" --header 'Content-Type: application/json' --data-raw "{\"status\": \"APPROVED\",\"authorized_cas\": [\"$CA_NAME\"] }")
echo $DMS_ENROLL_RESPONSE | jq -r .crt | sed 's/\r/\n/g' | sed -Ez '$ s/\n+$//' | base64 -d > dms.crt

#echo "5) Getting the CA certificates"

estclient cacerts -server $DOMAIN/api/devmanager -explicit root-ca.pem -out cacerts.pem