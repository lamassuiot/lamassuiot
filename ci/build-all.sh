#!/bin/bash

# Build all Docker images with tag "otaq"

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$ROOT_DIR"

echo "Building all Docker images with tag 'otaq'..."
echo "Working directory: $(pwd)"
echo ""

# List of all dockerfiles and their image names
declare -A IMAGES=(
    ["alerts.dockerfile"]="lamassuiot/alerts:otaq"
    ["aws-connector.dockerfile"]="lamassuiot/aws-connector:otaq"
    ["ca.dockerfile"]="lamassuiot/ca:otaq"
    ["devmanager.dockerfile"]="lamassuiot/devmanager:otaq"
    ["dmsmanager.dockerfile"]="lamassuiot/dmsmanager:otaq"
    ["goose-lamassu.dockerfile"]="lamassuiot/goose-lamassu:otaq"
    ["kms.dockerfile"]="lamassuiot/kms:otaq"
    ["monolithic.dockerfile"]="lamassuiot/monolithic:otaq"
    ["pq_alerts.dockerfile"]="lamassuiot/pq-alerts:otaq"
    ["pq_ca.dockerfile"]="lamassuiot/pq-ca:otaq"
    ["pq_devmanager.dockerfile"]="lamassuiot/pq-devmanager:otaq"
    ["pq_dmsmanager.dockerfile"]="lamassuiot/pq-dmsmanager:otaq"
    ["pq_va.dockerfile"]="lamassuiot/pq-va:otaq"
    ["va.dockerfile"]="lamassuiot/va:otaq"
)

TOTAL=${#IMAGES[@]}
CURRENT=0

for dockerfile in "${!IMAGES[@]}"; do
    CURRENT=$((CURRENT + 1))
    IMAGE_NAME="${IMAGES[$dockerfile]}"
    
    echo "[$CURRENT/$TOTAL] Building $IMAGE_NAME from ci/$dockerfile..."
    
    docker build -f "ci/$dockerfile" -t "$IMAGE_NAME" .
    
    if [ $? -eq 0 ]; then
        echo "✓ Successfully built $IMAGE_NAME"
    else
        echo "✗ Failed to build $IMAGE_NAME"
        exit 1
    fi
    echo ""
done

echo "=========================================="
echo "All $TOTAL images built successfully!"
echo "=========================================="
docker images | grep "lamassuiot.*otaq"
