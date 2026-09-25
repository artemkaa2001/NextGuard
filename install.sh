#!/bin/sh
set -eu

die() { printf 'NextGuard: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "run as root: sudo ./install.sh"
[ -d /run/systemd/system ] || die "systemd is required"
command -v python3 >/dev/null || die "Python 3 is required"

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
for command in /usr/local/bin/nextguard /usr/local/bin/guard; do
    if [ -e "$command" ] || [ -L "$command" ]; then
        target=$(readlink "$command" 2>/dev/null || true)
        [ "$target" = "/opt/nextguard/bin/nextguard" ] || die "$command already exists and is not owned by NextGuard"
    fi
done

if ! command -v ipset >/dev/null || ! command -v iptables >/dev/null; then
    command -v apt-get >/dev/null || die "install ipset and iptables using your distribution package manager"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y ipset iptables
fi

install -d -m 0755 /opt/nextguard /opt/nextguard/bin /etc/nextguard /var/lib/nextguard/sources /var/lib/nextguard/generations /var/log/nextguard
cp -a "$ROOT/nextguard" /opt/nextguard/
install -m 0755 "$ROOT/bin/nextguard" /opt/nextguard/bin/nextguard
install -m 0755 "$ROOT/bin/ping-control" /opt/nextguard/bin/ping-control
install -m 0755 "$ROOT/uninstall.sh" /opt/nextguard/uninstall.sh
install -m 0644 "$ROOT/config/sources.json" /etc/nextguard/sources.json
if [ ! -e /etc/nextguard/config.json ]; then
    printf '%s\n' '{"schema":1,"configured":false,"language":"ru","interval_minutes":60,"modules":{"rkn":false,"attackers":false,"scanners":false,"ping":false},"logging":{"rkn":true,"attackers":true,"scanners":true,"ping":true},"interfaces":[]}' > /etc/nextguard/config.json
fi
chmod 0600 /etc/nextguard/config.json
install -m 0644 "$ROOT"/systemd/*.service "$ROOT"/systemd/*.timer /etc/systemd/system/
install -m 0644 "$ROOT/logrotate/nextguard" /etc/logrotate.d/nextguard
ln -sfn /opt/nextguard/bin/nextguard /usr/local/bin/nextguard
ln -sfn /opt/nextguard/bin/nextguard /usr/local/bin/guard
systemctl daemon-reload
systemctl enable nextguard.service
systemctl enable --now nextguard-update.timer nextguard-log.service
printf 'NextGuard installed. Run: sudo nextguard\n'
if [ -t 0 ] || [ -r /dev/tty ]; then exec /usr/local/bin/nextguard; fi
printf 'No TTY; configure later with: sudo nextguard\n'
