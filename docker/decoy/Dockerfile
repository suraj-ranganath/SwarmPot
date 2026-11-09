# syntax=docker/dockerfile:1
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server passwd ca-certificates procps \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /usr/local/bin/gateway-shell --uid 1000 admin \
    && echo 'admin:migration2024' | chpasswd \
    && mkdir -p /run/sshd /var/log/gateway

COPY docker/decoy/sshd_config /etc/ssh/sshd_config
COPY docker/decoy/entrypoint.sh /usr/local/bin/gateway-entrypoint
COPY docker/decoy/gateway-shell /usr/local/bin/gateway-shell
COPY docker/decoy/gateway-bashrc /etc/gateway/bashrc

RUN chmod 0755 /usr/local/bin/gateway-entrypoint /usr/local/bin/gateway-shell \
    && chmod 0644 /etc/gateway/bashrc

EXPOSE 22
ENTRYPOINT ["/usr/local/bin/gateway-entrypoint"]
