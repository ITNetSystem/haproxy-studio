#!/bin/sh
# Installs the application only. Never installs, rewrites or reloads HAProxy.
set -eu
if [ "$(id -u)" -ne 0 ]; then echo 'Run as root (sudo sh scripts/install.sh).' >&2; exit 1; fi
command -v python3 >/dev/null || { echo 'Install Python 3.9+ using apt/dnf first.' >&2; exit 1; }
python3 -c 'import sys; assert sys.version_info >= (3,9), "Python 3.9+ required"'
command -v systemctl >/dev/null || { echo 'systemd required; otherwise use Docker or run python3 -m haproxy_studio.' >&2; exit 1; }
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
install -d -m 755 /opt/haproxy-studio /etc/haproxy-studio
install -d -m 700 /var/lib/haproxy-studio
# Copy executable sources only, never development state or private settings.
cp -R "$source_dir/haproxy_studio" /opt/haproxy-studio/
if [ ! -f /etc/haproxy-studio/config.json ]; then
  install -m 600 "$source_dir/config.example.json" /etc/haproxy-studio/config.json
fi
install -m 644 "$source_dir/deploy/haproxy-studio.service" /etc/systemd/system/haproxy-studio.service
systemctl daemon-reload
printf '%s\n' 'Installed. Review /etc/haproxy-studio/config.json, then:' 'systemctl enable --now haproxy-studio' 'Initial password: /var/lib/haproxy-studio/initial-password' 'Default: read-only, http://127.0.0.1:9130/haproxy-admin/'
