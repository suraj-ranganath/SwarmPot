#!/usr/bin/env bash
set -euo pipefail

: "${UPSTREAM_HOST:=target}"
: "${UPSTREAM_PORT:=9090}"
: "${UPSTREAM_GRADER_PORT:=9091}"
: "${SIDECAR_LOG:=/logs/sidecar.jsonl}"

mkdir -p "$(dirname "$SIDECAR_LOG")"

# Freeze the public-route inventory before either proxy becomes healthy.
python -m swarmpot.breadcrumbs

# 9090: HTTP application through the lure-inserting reverse proxy.
mitmdump \
  --quiet \
  --mode "reverse:http://${UPSTREAM_HOST}:${UPSTREAM_PORT}" \
  --listen-host 0.0.0.0 \
  --listen-port 9090 \
  --set keep_host_header=true \
  --set connection_strategy=lazy \
  -s /opt/sidecar/swarmpot/sidecar.py &

# 9091: the official verifier/upload endpoint. Byte-for-byte TCP passthrough:
# the grader is never inspected or modified by SwarmPot.
socat TCP-LISTEN:9091,fork,reuseaddr TCP:${UPSTREAM_HOST}:${UPSTREAM_GRADER_PORT} &

trap 'kill $(jobs -p) 2>/dev/null || true' INT TERM
wait -n
