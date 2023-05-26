#!/bin/bash

# Check if table exists, if not, create it
if aws dynamodb describe-table --table-name $TABLE_NAME --endpoint-url http://dynamodb-local:8000 --region us-west-2 2>/dev/null; then
  echo "DynamoDB Table: $TABLE_NAME found, Skipping DynamoDB table creation..."
else 
  echo "DynamoDB Table: $TABLE_NAME not found, Creating DynamoDB table..."
  aws dynamodb create-table --table-name lamassuiot --attribute-definitions AttributeName=PK,AttributeType=S AttributeName=SK,AttributeType=S --key-schema AttributeName=PK,KeyType=HASH AttributeName=SK,KeyType=RANGE --provisioned-throughput ReadCapacityUnits=1,WriteCapacityUnits=1 --endpoint-url http://dynamodb-local:8000 --region us-west-2 
fi