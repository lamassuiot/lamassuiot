package dynamodb

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func createDynamoDBConnection(ctx context.Context, region, accessKeyID, secretAccessKey, url string) (*dynamodb.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.StaticCredentialsProvider{
			Value: aws.Credentials{
				AccessKeyID:     accessKeyID,
				SecretAccessKey: secretAccessKey,
			},
		}),
		config.WithEndpointResolverWithOptions(aws.EndpointResolverWithOptionsFunc(
			func(service, region string, options ...interface{}) (aws.Endpoint, error) {
				return aws.Endpoint{URL: url}, nil
			},
		)),
	)

	if err != nil {
		return nil, err
	}
	client := dynamodb.NewFromConfig(cfg)
	return client, nil
}

type dynamoDBQuerier[E any] struct {
	*dynamodb.Client
	tableName string
}

type DynamoDBItem[E any] struct {
	PK   string
	SK   string
	item E
}

func (item *DynamoDBItem[E]) GetKeys() (map[string]types.AttributeValue, error) {
	pk, err := attributevalue.Marshal(item.PK)
	if err != nil {
		return nil, err
	}
	sk, err := attributevalue.Marshal(item.SK)
	if err != nil {
		return nil, err
	}
	return map[string]types.AttributeValue{"PK": pk, "SK": sk}, nil
}

func (item *DynamoDBItem[E]) Marshal() (map[string]types.AttributeValue, error) {
	elem, err := attributevalue.MarshalMap(item.item)
	if err != nil {
		return nil, err
	}
	keys, err := item.GetKeys()
	if err != nil {
		return nil, err
	}
	out := map[string]types.AttributeValue{
		"PK": keys["PK"],
		"SK": keys["SK"],
	}
	for k, v := range elem {
		out[k] = v
	}
	return out, nil
}

func (item *DynamoDBItem[E]) Unmarshal(out map[string]types.AttributeValue) (*E, error) {
	if out == nil {
		return nil, nil
	}
	err := attributevalue.UnmarshalMap(out, &item.item)
	if err != nil {
		return nil, err
	}
	return &item.item, nil
}

func newDynamoDBQuerier[E any](client *dynamodb.Client, tableName string) dynamoDBQuerier[E] {
	return dynamoDBQuerier[E]{
		Client:    client,
		tableName: tableName,
	}
}

func (client *dynamoDBQuerier[E]) Select(ctx context.Context, PK, SK string) (*E, error) {
	dbItem := &DynamoDBItem[E]{
		PK: PK,
		SK: SK,
	}
	key, err := dbItem.GetKeys()
	if err != nil {
		return nil, err
	}
	out, err := client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(client.tableName),
		Key:       key,
	})
	if err != nil {
		return nil, err
	}
	return dbItem.Unmarshal(out.Item)
}

func (client *dynamoDBQuerier[E]) Insert(ctx context.Context, elem E, PK, SK string) (*E, error) {
	dbItem := &DynamoDBItem[E]{
		PK:   PK,
		SK:   SK,
		item: elem,
	}
	item, err := dbItem.Marshal()
	if err != nil {
		return nil, err
	}
	expr, err := expression.NewBuilder().WithCondition(expression.AttributeNotExists(expression.Name("PK"))).Build()
	if err != nil {
		return nil, err
	}
	_, err = client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:                 aws.String(client.tableName),
		Item:                      item,
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		ConditionExpression:       expr.Condition(),
	})
	if err != nil {
		return nil, err
	}
	return client.Select(ctx, PK, SK)
}

func (client *dynamoDBQuerier[E]) Update(ctx context.Context, elem E, PK, SK string) (*E, error) {
	dbItem := &DynamoDBItem[E]{
		PK:   PK,
		SK:   SK,
		item: elem,
	}
	item, err := dbItem.Marshal()
	if err != nil {
		return nil, err
	}
	expr, err := expression.NewBuilder().WithCondition(expression.AttributeExists(expression.Name("PK"))).Build()
	if err != nil {
		return nil, err
	}
	_, err = client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:                 aws.String(client.tableName),
		Item:                      item,
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		ConditionExpression:       expr.Condition(),
	})
	if err != nil {
		return nil, err
	}
	return client.Select(ctx, PK, SK)
}

func (client *dynamoDBQuerier[E]) Delete(ctx context.Context, PK, SK string) error {
	dbItem := &DynamoDBItem[E]{
		PK: PK,
		SK: SK,
	}
	key, err := dbItem.GetKeys()
	if err != nil {
		return err
	}
	_, err = client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(client.tableName),
		Key:       key,
	})
	if err != nil {
		return err
	}
	return nil
}

func (client *dynamoDBQuerier[E]) Clean(ctx context.Context) error {
	descr, err := client.DescribeTable(ctx, &dynamodb.DescribeTableInput{
		TableName: aws.String(client.tableName),
	})
	if err != nil {
		return err
	}
	keySchema := descr.Table.KeySchema
	var attributesToGet []string
	for _, elem := range keySchema {
		attributesToGet = append(attributesToGet, *elem.AttributeName)
	}
	scan, err := client.Scan(ctx, &dynamodb.ScanInput{
		TableName:       aws.String(client.tableName),
		AttributesToGet: attributesToGet,
		ConsistentRead:  aws.Bool(true),
	})
	if err != nil {
		return err
	}
	items := scan.Items
	if len(items) == 0 {
		return nil
	}
	var deleteRequests []types.WriteRequest
	for _, item := range items {
		deleteRequests = append(deleteRequests, types.WriteRequest{DeleteRequest: &types.DeleteRequest{Key: itemToKey(item, keySchema)}})
	}
	_, err = client.BatchWriteItem(ctx, &dynamodb.BatchWriteItemInput{
		RequestItems: map[string][]types.WriteRequest{
			client.tableName: deleteRequests,
		},
	})
	if err != nil {
		return err
	}
	return nil
}

func itemToKey(item map[string]types.AttributeValue, keySchema []types.KeySchemaElement) map[string]types.AttributeValue {
	key := make(map[string]types.AttributeValue)
	for _, elem := range keySchema {
		key[*elem.AttributeName] = item[*elem.AttributeName]
	}
	return key
}
