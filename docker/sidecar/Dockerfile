# syntax=docker/dockerfile:1
FROM python:3.11-slim-bookworm

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates socat && rm -rf /var/lib/apt/lists/*
RUN pip install "mitmproxy>=11,<12"

COPY swarmpot/__init__.py swarmpot/sidecar.py swarmpot/breadcrumbs.py /opt/sidecar/swarmpot/
ENV PYTHONPATH=/opt/sidecar
COPY docker/sidecar/entrypoint.sh /usr/local/bin/sidecar-entrypoint
RUN chmod 0755 /usr/local/bin/sidecar-entrypoint

ENTRYPOINT ["/usr/local/bin/sidecar-entrypoint"]
