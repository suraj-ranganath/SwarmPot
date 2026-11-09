#!/bin/sh
set -eu

: "${GATEWAY_LOG_DIR:=/var/log/gateway}"
mkdir -p "$GATEWAY_LOG_DIR" /run/sshd
chmod 0777 "$GATEWAY_LOG_DIR"

# The shared home is bind-mounted from the run directory. It may be owned by
# the host user; make it writable for the in-container `admin` account (uid 1000).
chown -R admin:admin /home/admin 2>/dev/null || true
chmod -R a+rwX /home/admin 2>/dev/null || true

ssh-keygen -A
exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config
