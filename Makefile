TEST_FLAGS="-cover"

test_engines:
	# go test $(TEST_FLAGS) ./engines/crypto/vaultkv2/
	# go test $(TEST_FLAGS) ./engines/crypto/vaultkv2/docker/
	go test $(TEST_FLAGS) ./engines/crypto/filesystem/
	# go test $(TEST_FLAGS) ./engines/crypto/aws/
	# go test $(TEST_FLAGS) ./engines/crypto/pkcs11/
	go test $(TEST_FLAGS) ./engines/crypto/software/
	go test $(TEST_FLAGS) ./engines/storage/postgres/test
	go test $(TEST_FLAGS) ./engines/storage/postgres/test/
	go test $(TEST_FLAGS) ./engines/storage/postgres/migrations_test/
	# go test $(TEST_FLAGS) ./engines/eventbus/aws/
	# go test $(TEST_FLAGS) ./engines/eventbus/amqp/
	# go test $(TEST_FLAGS) ./engines/eventbus/amqp/test

test_backend:
	go test $(TEST_FLAGS) ./backend/pkg/jobs/
	go test $(TEST_FLAGS) ./backend/pkg/services/alerts/event_filters/
	go test $(TEST_FLAGS) ./backend/pkg/routes/
	go test $(TEST_FLAGS) ./backend/pkg/routes/middlewares/basic-header-extractors/
	go test $(TEST_FLAGS) ./backend/pkg/routes/middlewares/identity-extractors/
	go test $(TEST_FLAGS) ./backend/pkg/routes/middlewares/identity-extractors/client-certificate-extractor/
	go test $(TEST_FLAGS) ./backend/pkg/cryptoengines/builder/
	go test $(TEST_FLAGS) ./backend/pkg/helpers/
	go test $(TEST_FLAGS) ./backend/pkg/helpers/slices/
	go test $(TEST_FLAGS) ./backend/pkg/helpers/
	go test $(TEST_FLAGS) ./backend/pkg/x509engines/
	go test $(TEST_FLAGS) ./backend/pkg/assemblers/tests/ca/
	go test $(TEST_FLAGS) ./backend/pkg/assemblers/tests/va/
	go test $(TEST_FLAGS) ./backend/pkg/assemblers/tests/kms/
	go test $(TEST_FLAGS) ./backend/pkg/assemblers/tests/alerts/
	go test $(TEST_FLAGS) ./backend/pkg/assemblers/tests/dms-manager/
	go test $(TEST_FLAGS) ./backend/pkg/assemblers/tests/device-manager/
	go test $(TEST_FLAGS) ./backend/pkg/storage/builder/
	go test $(TEST_FLAGS) ./backend/pkg/middlewares/eventpub/

test_connectors:
	go test $(TEST_FLAGS) ./connectors/awsiot/pkg/

test_shared:
	go test $(TEST_FLAGS) ./shared/subsystems/pkg/test/subsystems/
	go test $(TEST_FLAGS) ./shared/http/pkg/helpers/

test_core:
	go test $(TEST_FLAGS) ./core/pkg/engines/cryptoengines/
	go test $(TEST_FLAGS) ./core/pkg/engines/storage/
	go test $(TEST_FLAGS) ./core/pkg/engines/eventbus/
	go test $(TEST_FLAGS) ./core/pkg/services/eventhandling/
	go test $(TEST_FLAGS) ./core/pkg/helpers/
	go test $(TEST_FLAGS) ./core/pkg/config/
	go test $(TEST_FLAGS) ./core/pkg/models/

test: test_engines test_backend test_connectors test_shared test_shared test_core

format_code:
	gofmt -l -s -w .

run:
	go run $(TEST_FLAGS) ./monolithic/cmd/development/main.go
