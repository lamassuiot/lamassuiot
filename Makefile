
DIR := $(shell pwd)

build-monolithic: 
	@echo "Building monolithic..."
	@cd monolithic; go build -o $(DIR)/target/lamassuiot cmd/development/main.go

plugins: filesystem pkcs11 aws vaultkv2 amqp aws-eventbus channel couchdb postgres sqlite
	@echo "Plugins built successfully. Check $(DIR)/target/plugins"

pkcs11:
	@echo "Building pkcs11..."
#	@cd engines/crypto/pkcs11; go build -buildmode=plugin -trimpath -a -gcflags=all="-l -B" -ldflags="-s -w" -o $(DIR)/target/plugins/pkcs11.so
	@cd backend; go build -buildmode=plugin -a -o $(DIR)/target/plugins/pkcs11.so github.com/lamassuiot/lamassuiot/v3/engines/crypto/pkcs11

filesystem:
	@echo "Building filesystem..."
	@cd backend; go build -buildmode=plugin -a -o $(DIR)/target/plugins/filesystem.so github.com/lamassuiot/lamassuiot/v3/engines/crypto/filesystem

aws:
	@echo "Building aws..."
	@cd backend; go build -buildmode=plugin -a -o $(DIR)/target/plugins/aws.so github.com/lamassuiot/lamassuiot/v3/engines/crypto/aws

vaultkv2:
	@echo "Building vaultkv2..."
	@cd backend; go build -buildmode=plugin -a -o $(DIR)/target/plugins/vaultkv2.so github.com/lamassuiot/lamassuiot/v3/engines/crypto/vaultkv2

amqp:
	@echo "Building amqp..."
	@cd backend; go build -buildmode=plugin -a -o $(DIR)/target/plugins/amqp.so github.com/lamassuiot/lamassuiot/v3/engines/eventbus/amqp

aws-eventbus:
	@echo "Building aws-eventbus..."
	@cd backend; go build -buildmode=plugin -a -o $(DIR)/target/plugins/aws-eventbus.so github.com/lamassuiot/lamassuiot/v3/engines/eventbus/aws

channel:
	@echo "Building channel..."
	@cd backend; go build -buildmode=plugin -a -o $(DIR)/target/plugins/channel.so github.com/lamassuiot/lamassuiot/v3/engines/eventbus/channel

couchdb:
	@echo "Building couchdb..."
	@cd backend; go build -buildmode=plugin -tags experimental -a -o $(DIR)/target/plugins/couchdb.so github.com/lamassuiot/lamassuiot/v3/engines/storage/couchdb

postgres:
	@echo "Building postgres..."
	@cd backend; go build -buildmode=plugin -a -o $(DIR)/target/plugins/postgres.so github.com/lamassuiot/lamassuiot/v3/engines/storage/postgres

sqlite:
	@echo "Building sqlite..."
	@cd backend; go build -buildmode=plugin -tags experimental -a -o $(DIR)/target/plugins/sqlite.so github.com/lamassuiot/lamassuiot/v3/engines/storage/sqlite

clean:
	@rm -rf $(DIR)/target/plugins
	@echo "Cleaned up plugins"

test:
	@cd backend; go test  -timeout 360s -tags experimental -run ^TestCryptoEngines$ github.com/lamassuiot/lamassuiot/v3/backend/pkg/assemblers