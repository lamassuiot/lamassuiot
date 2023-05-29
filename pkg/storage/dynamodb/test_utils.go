package dynamodb

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func CreateCustomer(ctx context.Context, client *dynamodb.Client, customerName string, tableName string) error {
	item := map[string]interface{}{
		"PK":   "Customer#" + customerName,
		"SK":   "Customer#" + customerName,
		"Name": customerName,
	}
	dbItem, err := attributevalue.MarshalMap(item)
	if err != nil {
		return err
	}
	_, err = client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item:      dbItem,
	})
	return err
}

func itemToKey(item map[string]types.AttributeValue, keySchema []types.KeySchemaElement) map[string]types.AttributeValue {
	key := make(map[string]types.AttributeValue)
	for _, elem := range keySchema {
		key[*elem.AttributeName] = item[*elem.AttributeName]
	}
	return key
}

func Clean(t *testing.T, ctx context.Context, client *dynamodb.Client, tableName string) {
	descr, err := client.DescribeTable(ctx, &dynamodb.DescribeTableInput{
		TableName: aws.String(tableName),
	})
	if err != nil {
		t.Fatalf("Unable to describe table %s", tableName)
	}
	keySchema := descr.Table.KeySchema
	var attributesToGet []string
	for _, elem := range keySchema {
		attributesToGet = append(attributesToGet, *elem.AttributeName)
	}
	scan, err := client.Scan(ctx, &dynamodb.ScanInput{
		TableName:       aws.String(tableName),
		AttributesToGet: attributesToGet,
		ConsistentRead:  aws.Bool(true),
	})
	if err != nil {
		t.Fatalf("Unable to scan table %s", tableName)
	}
	items := scan.Items
	if len(items) == 0 {
		return
	}
	var deleteRequests []types.WriteRequest
	for _, item := range items {
		deleteRequests = append(deleteRequests, types.WriteRequest{DeleteRequest: &types.DeleteRequest{Key: itemToKey(item, keySchema)}})
	}
	_, err = client.BatchWriteItem(ctx, &dynamodb.BatchWriteItemInput{
		RequestItems: map[string][]types.WriteRequest{
			tableName: deleteRequests,
		},
	})
	if err != nil {
		t.Fatalf("Unable to delete table %s items", tableName)
	}
}
