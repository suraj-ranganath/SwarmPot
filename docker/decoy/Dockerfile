# syntax=docker/dockerfile:1
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server passwd ca-certificates procps \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /usr/local/bin/decoy-shell --uid 1000 admin \
    && echo 'admin:swarmpot' | chpasswd \
    && mkdir -p /run/sshd /var/log/decoy

COPY docker/decoy/sshd_config /etc/ssh/sshd_config
COPY docker/decoy/entrypoint.sh /usr/local/bin/decoy-entrypoint
COPY docker/decoy/decoy-shell /usr/local/bin/decoy-shell
COPY docker/decoy/bashrc /etc/decoy/bashrc

RUN chmod 0755 /usr/local/bin/decoy-entrypoint /usr/local/bin/decoy-shell \
    && chmod 0644 /etc/decoy/bashrc

EXPOSE 22
ENTRYPOINT ["/usr/local/bin/decoy-entrypoint"]
