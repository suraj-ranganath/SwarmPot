#!/bin/sh
set -eu

: "${DECOY_LOG_DIR:=/var/log/decoy}"
mkdir -p "$DECOY_LOG_DIR" /run/sshd
chmod 0777 "$DECOY_LOG_DIR"

# The shared home is bind-mounted from the episode directory. It may be owned by
# the host user; make it writable for the in-container `admin` account (uid 1000).
chown -R admin:admin /home/admin 2>/dev/null || true
chmod -R a+rwX /home/admin 2>/dev/null || true

ssh-keygen -A
exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config
