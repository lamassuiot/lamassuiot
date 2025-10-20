.PHONY: build build-docker run clean help

BINARY_NAME=migrate-db
DOCKER_IMAGE=lamassu/migrate-db
VERSION?=latest

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the migration tool binary
	@echo "Building $(BINARY_NAME)..."
	go build -o $(BINARY_NAME) .
	@echo "Build complete: ./$(BINARY_NAME)"

build-docker: ## Build Docker image
	@echo "Building Docker image $(DOCKER_IMAGE):$(VERSION)..."
	cd ../../../../../ && docker build -f engines/storage/postgres/cmd/migrate-db/Dockerfile -t $(DOCKER_IMAGE):$(VERSION) .
	@echo "Docker build complete: $(DOCKER_IMAGE):$(VERSION)"

run: build ## Build and run the migration tool (requires environment variables)
	@echo "Running $(BINARY_NAME)..."
	./$(BINARY_NAME) $(ARGS)

clean: ## Clean build artifacts
	@echo "Cleaning..."
	rm -f $(BINARY_NAME)
	@echo "Clean complete"

install: build ## Install the binary to $GOPATH/bin
	@echo "Installing $(BINARY_NAME) to $(GOPATH)/bin..."
	mv $(BINARY_NAME) $(GOPATH)/bin/
	@echo "Install complete"

# Example targets
example-single: build ## Example: Migrate a single database
	./$(BINARY_NAME) -hostname=localhost -username=postgres -password=postgres -database=ca

example-all: build ## Example: Migrate all databases
	./$(BINARY_NAME) -hostname=localhost -username=postgres -password=postgres -all

example-status: build ## Example: Check migration status
	./$(BINARY_NAME) -hostname=localhost -username=postgres -password=postgres -database=ca -status

example-docker: build-docker ## Example: Run migration in Docker
	docker run --rm \
		-e POSTGRES_HOSTNAME=host.docker.internal \
		-e POSTGRES_USERNAME=postgres \
		-e POSTGRES_PASSWORD=postgres \
		$(DOCKER_IMAGE):$(VERSION) \
		-database=ca
