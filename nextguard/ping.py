from __future__ import annotations

from .firewall import run

CHAIN = "NEXTGUARD_PING"
PREFIX = "NEXTGUARD_PING "


def _chain() -> bool:
    return run(["iptables", "-w", "-nL", CHAIN], check=False).returncode == 0


def enable(logging_enabled: bool = True) -> None:
    if not _chain():
        run(["iptables", "-w", "-N", CHAIN])
    run(["iptables", "-w", "-F", CHAIN])
    match = ["-p", "icmp", "--icmp-type", "echo-request"]
    if logging_enabled:
        run(["iptables", "-w", "-A", CHAIN, *match, "-m", "limit", "--limit", "10/second", "--limit-burst", "20", "-j", "LOG", "--log-prefix", PREFIX])
    run(["iptables", "-w", "-A", CHAIN, *match, "-j", "DROP"])
    run(["iptables", "-w", "-A", CHAIN, "-j", "RETURN"])
    if run(["iptables", "-w", "-C", "INPUT", "-j", CHAIN], check=False).returncode != 0:
        # List matching is inserted at position one; ping follows it, preserving list provenance.
        run(["iptables", "-w", "-I", "INPUT", "2", "-j", CHAIN])


def disable() -> None:
    while run(["iptables", "-w", "-C", "INPUT", "-j", CHAIN], check=False).returncode == 0:
        run(["iptables", "-w", "-D", "INPUT", "-j", CHAIN])
    if _chain():
        run(["iptables", "-w", "-F", CHAIN])
        run(["iptables", "-w", "-X", CHAIN])
