# syntax=docker/dockerfile:1
# Cowrie proxy mode, built from the pinned vendor checkout.
FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SETUPTOOLS_SCM_PRETEND_VERSION_FOR_COWRIE=2.9.0 \
    COWRIE_STDOUT=yes

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libssl-dev libffi-dev libsnappy-dev procps \
    && rm -rf /var/lib/apt/lists/*

COPY vendor/cowrie /opt/cowrie-src
RUN pip install /opt/cowrie-src

RUN useradd --uid 999 --create-home --shell /usr/sbin/nologin cowrie \
    && mkdir -p /cowrie/etc /cowrie/var/run /var/log/cowrie /var/lib/cowrie

COPY docker/cowrie/cowrie.cfg /cowrie/etc/cowrie.cfg
COPY docker/cowrie/cowrie.cfg /etc/cowrie/cowrie.cfg
COPY docker/cowrie/userdb.txt /etc/cowrie/userdb.txt

RUN chown -R cowrie:cowrie /cowrie /var/log/cowrie /var/lib/cowrie

WORKDIR /cowrie
USER 999:999
EXPOSE 2222
CMD ["cowrie", "start"]
