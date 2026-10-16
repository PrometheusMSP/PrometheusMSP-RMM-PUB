#!/usr/bin/env sh
set -eu

if [ "$(id -u)" -ne 0 ]; then echo "Run as root" >&2; exit 1; fi
: "${PROMETHEUS_SERVER_URL:?set PROMETHEUS_SERVER_URL}"
: "${PROMETHEUS_ENROLLMENT_TOKEN:?set a short-lived PROMETHEUS_ENROLLMENT_TOKEN}"

src=${1:-./dist/prometheus-rmm-agent-linux-amd64}
install -o root -g root -m 0755 "$src" /usr/local/sbin/prometheus-rmm-agent
install -d -o root -g root -m 0700 /var/lib/prometheus-rmm
install -d -o root -g root -m 0750 /etc/prometheus-rmm
case "$PROMETHEUS_SERVER_URL$PROMETHEUS_ENROLLMENT_TOKEN" in *[[:space:]]*) echo "URL/token contains whitespace" >&2; exit 1;; esac
bootstrap_line=
if [ -n "${PROMETHEUS_BOOTSTRAP_CA_FILE:-}" ]; then
  install -o root -g root -m 0644 "$PROMETHEUS_BOOTSTRAP_CA_FILE" /etc/prometheus-rmm/bootstrap-ca.crt
  bootstrap_line='PROMETHEUS_BOOTSTRAP_CA_FILE=/etc/prometheus-rmm/bootstrap-ca.crt'
fi
printf 'PROMETHEUS_SERVER_URL=%s\nPROMETHEUS_ENROLLMENT_TOKEN=%s\nPROMETHEUS_STATE_DIR=/var/lib/prometheus-rmm\nPROMETHEUS_DRY_RUN=true\n%s\n' \
  "$PROMETHEUS_SERVER_URL" "$PROMETHEUS_ENROLLMENT_TOKEN" "$bootstrap_line" > /etc/prometheus-rmm/agent.env
chmod 0600 /etc/prometheus-rmm/agent.env
install -m 0644 "$(dirname "$0")/../deploy/prometheus-rmm-agent.service" /etc/systemd/system/prometheus-rmm-agent.service
systemctl daemon-reload
systemctl enable --now prometheus-rmm-agent.service
unset PROMETHEUS_ENROLLMENT_TOKEN
