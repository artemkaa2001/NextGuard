#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo "Run as root: sudo nextguard uninstall" >&2; exit 1; }
if [ "${1:-}" != "--confirmed" ]; then
    printf 'Type REMOVE to remove NextGuard rules and code: '
    IFS= read -r answer || exit 1
    [ "$answer" = REMOVE ] || { echo "Cancelled"; exit 0; }
fi
for unit in nextguard-update.timer nextguard-update.service nextguard-log.service nextguard-ping.service nextguard.service; do
    systemctl disable --now "$unit" >/dev/null 2>&1 || true
done
PYTHONPATH=/opt/nextguard /usr/bin/python3 -c 'from nextguard.ping import disable; disable()' 2>/dev/null || true
PYTHONPATH=/opt/nextguard /usr/bin/python3 -c 'from nextguard.firewall import cleanup; cleanup()' 2>/dev/null || true
rm -f /etc/systemd/system/nextguard.service /etc/systemd/system/nextguard-update.service /etc/systemd/system/nextguard-update.timer /etc/systemd/system/nextguard-log.service /etc/systemd/system/nextguard-ping.service /etc/logrotate.d/nextguard
[ "$(readlink /usr/local/bin/nextguard 2>/dev/null || true)" = /opt/nextguard/bin/nextguard ] && rm -f /usr/local/bin/nextguard
[ "$(readlink /usr/local/bin/guard 2>/dev/null || true)" = /opt/nextguard/bin/nextguard ] && rm -f /usr/local/bin/guard
rm -rf /opt/nextguard
systemctl daemon-reload
printf 'NextGuard removed. Existing firewall policy and packages were not changed.\nConfiguration, caches, and logs remain under /etc/nextguard, /var/lib/nextguard, and /var/log/nextguard.\n'
