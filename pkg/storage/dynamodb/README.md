Lamassu IoT
===================

<img src="https://www.lamassu.io/assets/brand/lamassu-brand.png" alt="Lamassu App" title="Lamassu" />

Lamassu is an IoT first PKI designed for industrial scenarios. This is the main code repository for Lamassu IoT where the product logic is being implemented. If you are looking for deployment instructions, please check the [docs](https://www.lamassu.io/docs/) or the project's [Docker Compose repository](https://github.com/lamassuiot/lamassu-compose).

## Running Unit tests for DynamoDB storage service

DynamoDB storage tests are executed based on AWS provided [DynamoDB Local](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DynamoDBLocal.html) service. 

In order to run DynamoDB Local and create a DynamoDB table, first of all, set up the docker containers with ```docker-compose up```. The DynamoDB Local Docker image uses the ```entrypoint.sh``` bash script located in ```./aws``` folder to create the DynamoDB table with the ```$TABLE_NAME``` environment variable specified in the ```docker-compose.yml``` file.

Now, you are ready to test!

```
go test
```