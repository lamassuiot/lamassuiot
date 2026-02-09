#!/usr/bin/env bash
set -euo pipefail

# Build all PQ Docker images with tag 'otaq' and handle local pqc-cloudflare-go

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
PQ_LOCAL="/home/alvaro/pqc-cloudflare-go"
TMP_COPY="$REPO_ROOT/pqc-cloudflare-go"
CLEAN_COPY=false
TAG="otaq"

cd "$REPO_ROOT"



# Find pq dockerfiles and build them
shopt -s nullglob
DOCKERFILES=("$REPO_ROOT"/ci/pq_kms.dockerfile)
if [ ${#DOCKERFILES[@]} -eq 0 ]; then
  echo "No pq_*.dockerfile found in $REPO_ROOT/ci" >&2
  exit 1
fi

for df in "${DOCKERFILES[@]}"; do
  fname=$(basename "$df")
  # pq_alerts.dockerfile -> alerts
  name=${fname#pq_}
  name=${name%.dockerfile}
  imagename="ghcr.io/lamassuiot/lamassu-${name}:${TAG}"

  echo "\n--- Building $imagename from $df (context: $REPO_ROOT) ---"
  if docker build --progress=plain -f "$df" -t "$imagename" "$REPO_ROOT"; then
    echo "Built $imagename"
  else
    echo "Build failed for $imagename" >&2
    exit 1
  fi
done

echo "\nAll PQ images built and tagged with :$TAG"

docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}" | grep "lamassuiot/lamassu-pq" || true
