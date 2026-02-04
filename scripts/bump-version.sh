#!/bin/bash
set -e

if [ -z "$1" ]; then
  echo "Usage: $0 <new-version>"
  echo "Example: $0 3.7.0"
  exit 1
fi

NEW_VERSION="$1"
MAJOR_VERSION=$(echo "$NEW_VERSION" | cut -d. -f1)

echo "Bumping all internal module dependencies to v${NEW_VERSION}..."

# Define all modules that need to be updated
MODULES=(
  "core"
  "sdk"
  "shared/aws"
  "shared/subsystems"
  "shared/http"
  "engines/crypto/aws"
  "engines/crypto/filesystem"
  "engines/crypto/software"
  "engines/crypto/pkcs11"
  "engines/crypto/vaultkv2"
  "engines/eventbus/amqp"
  "engines/eventbus/aws"
  "engines/storage/postgres"
  "engines/fs-storage/localfs"
  "engines/fs-storage/s3"
  "backend"
  "connectors/awsiot"
  "monolithic"
)

# Update each module's go.mod file
for module in "${MODULES[@]}"; do
  GO_MOD_FILE="${module}/go.mod"
  
  if [ ! -f "$GO_MOD_FILE" ]; then
    echo "Warning: $GO_MOD_FILE not found, skipping..."
    continue
  fi
  
  echo "Updating $GO_MOD_FILE..."
  
  # Update all lamassuiot internal dependencies to the new version
  # This uses sed to replace version numbers for all internal modules
  sed -i "s|github.com/lamassuiot/lamassuiot/\([^[:space:]]*\)/v${MAJOR_VERSION} v[0-9.]*|github.com/lamassuiot/lamassuiot/\1/v${MAJOR_VERSION} v${NEW_VERSION}|g" "$GO_MOD_FILE"
done

echo ""
echo "Running go mod tidy on all modules..."

# Run go mod tidy in each module directory
for module in "${MODULES[@]}"; do
  if [ -d "$module" ]; then
    echo "Tidying $module..."
    (cd "$module" && go mod tidy)
  fi
done

echo ""
echo "✓ All modules updated to v${NEW_VERSION}"
echo ""
echo "Next steps:"
echo "1. Review the changes: git diff"
echo "2. Commit the changes: git add . && git commit -m 'chore: bump version to v${NEW_VERSION}'"
echo "3. Push to main: git push origin main"
