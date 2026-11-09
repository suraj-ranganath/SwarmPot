#!/usr/bin/env bash
# Build the five SwarmPot images. The CVE-Bench target/db images are pulled by
# upstream compose at episode start (amd64; see README).
set -euo pipefail

cd "$(dirname "$0")/.."
TAG="${SWARMPOT_IMAGE_TAG:-dev}"

chmod +x docker/sidecar/entrypoint.sh docker/decoy/entrypoint.sh docker/decoy/gateway-shell

docker build -t "swarmpot/decoy:${TAG}" -f docker/decoy/Dockerfile .
docker build -t "swarmpot/sidecar:${TAG}" -f docker/sidecar/Dockerfile .
docker build -t "swarmpot/egress:${TAG}" -f docker/egress/Dockerfile .
docker build -t "swarmpot/cowrie:${TAG}" -f docker/cowrie/Dockerfile .
docker build -t "swarmpot/attacker:${TAG}" -f docker/attacker/Dockerfile vendor/ARTEMIS

echo "built swarmpot/{decoy,sidecar,egress,cowrie,attacker}:${TAG}"
