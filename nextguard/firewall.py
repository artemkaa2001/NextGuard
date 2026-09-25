from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

SET = "nextguard_v4"
TEMP_SET = "nextguard_tmp_v4"
CHAIN = "NEXTGUARD_IN"
TEMP_CHAIN = "NEXTGUARD_NEW"
DOCKER_CHAIN = "DOCKER-USER"
PREFIX = "NEXTGUARD_DROP "


class FirewallError(RuntimeError):
    pass


def run(argv: list[str], *, stdin: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, input=stdin, text=True, capture_output=True, check=check)
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", "") or str(exc)
        raise FirewallError(f"{' '.join(argv[:2])}: {detail.strip()}") from exc


def require_tools() -> None:
    missing = [name for name in ("ipset", "iptables") if not shutil.which(name)]
    if missing:
        raise FirewallError("missing required commands: " + ", ".join(missing))


def _has_chain(name: str) -> bool:
    return run(["iptables", "-w", "-nL", name], check=False).returncode == 0


def _ensure_jump(parent: str, child: str) -> None:
    if not _has_chain(parent):
        return
    exists = run(["iptables", "-w", "-C", parent, "-j", child], check=False).returncode == 0
    if not exists:
        run(["iptables", "-w", "-I", parent, "1", "-j", child])


def apply(networks: list[str], logging_enabled: bool = True, interfaces: list[str] | None = None) -> None:
    """Build and swap one set, then install owned rules. The active set is never emptied."""
    require_tools()
    maxelem = max(65536, len(networks) * 2 + 1)
    run(["ipset", "destroy", TEMP_SET], check=False)
    script = [f"create {SET} hash:net family inet maxelem {maxelem} -exist",
              f"create {TEMP_SET} hash:net family inet maxelem {maxelem}"]
    script.extend(f"add {TEMP_SET} {network}" for network in networks)
    # restore must complete before swap; a failed add leaves the active set unchanged.
    run(["ipset", "restore"], stdin="\n".join(script) + "\n")
    try:
        # Build a complete replacement chain while the old chain remains attached.
        if _has_chain(TEMP_CHAIN):
            for parent in ("INPUT", DOCKER_CHAIN):
                while _has_chain(parent) and run(["iptables", "-w", "-C", parent, "-j", TEMP_CHAIN], check=False).returncode == 0:
                    run(["iptables", "-w", "-D", parent, "-j", TEMP_CHAIN])
            run(["iptables", "-w", "-F", TEMP_CHAIN]); run(["iptables", "-w", "-X", TEMP_CHAIN])
        run(["iptables", "-w", "-N", TEMP_CHAIN])
        scopes = interfaces or [None]
        for interface in scopes:
            match = (["-i", interface] if interface else []) + ["-m", "set", "--match-set", SET, "src"]
            if logging_enabled:
                run(["iptables", "-w", "-A", TEMP_CHAIN, *match, "-m", "limit", "--limit", "10/second", "--limit-burst", "20", "-j", "LOG", "--log-prefix", PREFIX])
            run(["iptables", "-w", "-A", TEMP_CHAIN, *match, "-j", "DROP"])
        run(["iptables", "-w", "-A", TEMP_CHAIN, "-j", "RETURN"])
        for parent in ("INPUT", DOCKER_CHAIN):
            if _has_chain(parent):
                run(["iptables", "-w", "-I", parent, "1", "-j", TEMP_CHAIN])
                while run(["iptables", "-w", "-C", parent, "-j", CHAIN], check=False).returncode == 0:
                    run(["iptables", "-w", "-D", parent, "-j", CHAIN])
        if _has_chain(CHAIN):
            run(["iptables", "-w", "-F", CHAIN]); run(["iptables", "-w", "-X", CHAIN])
        run(["iptables", "-w", "-E", TEMP_CHAIN, CHAIN])
        run(["ipset", "swap", TEMP_SET, SET])
    except Exception:
        raise
    finally:
        run(["ipset", "destroy", TEMP_SET], check=False)


def cleanup() -> None:
    for parent in ("INPUT", DOCKER_CHAIN):
        while _has_chain(parent) and run(["iptables", "-w", "-C", parent, "-j", CHAIN], check=False).returncode == 0:
            run(["iptables", "-w", "-D", parent, "-j", CHAIN])
    if _has_chain(CHAIN):
        run(["iptables", "-w", "-F", CHAIN])
        run(["iptables", "-w", "-X", CHAIN])
    run(["ipset", "destroy", SET], check=False)


def counters() -> str:
    result = run(["iptables", "-w", "-nvL", CHAIN], check=False)
    return result.stdout if result.returncode == 0 else ""


def restore_generation(path: Path) -> None:
    data = json.loads((path / "generation.json").read_text(encoding="utf-8"))
    apply(data["networks"], data.get("logging_enabled", True), data.get("interfaces", []))
