from __future__ import annotations

import collections
import datetime as dt
import ipaddress
import json
import re
import subprocess
from pathlib import Path

from .config import load
from .i18n import tr
from .paths import CURRENT, EVENT_LOG

FIELDS = re.compile(r"\b(SRC|DST|PROTO|SPT|DPT|TYPE)=([^ ]+)")
MAX_SIZE = 10 * 1024 * 1024


def rotate(path: Path) -> None:
    if not path.exists() or path.stat().st_size < MAX_SIZE:
        return
    Path(str(path) + ".5").unlink(missing_ok=True)
    for number in range(4, 0, -1):
        old, new = Path(f"{path}.{number}"), Path(f"{path}.{number + 1}")
        if old.exists():
            old.replace(new)
    path.replace(Path(str(path) + ".1"))


def build_index(generation: dict) -> dict[tuple[int, int], list[dict]]:
    index: dict[tuple[int, int], list[dict]] = {}
    for network, origins in generation.get("provenance", {}).items():
        value = ipaddress.ip_network(network)
        index.setdefault((value.prefixlen, int(value.network_address)), []).extend(origins)
    return index


def lookup(address: str, index: dict[tuple[int, int], list[dict]]) -> list[dict]:
    value, found = int(ipaddress.ip_address(address)), []
    # At most 33 dictionary probes, independent of list size.
    for prefix in range(33):
        mask = ((1 << 32) - 1) ^ ((1 << (32 - prefix)) - 1) if prefix else 0
        found.extend(index.get((prefix, value & mask), ()))
    return found


def format_event(line: str, cfg: dict, generation: dict, index: dict | None = None) -> str | None:
    values = dict(FIELDS.findall(line))
    src = values.get("SRC")
    if not src:
        return None
    origins = lookup(src, index if index is not None else build_index(generation)) if "NEXTGUARD_DROP" in line else []
    enabled = cfg["logging"]
    origins = [x for x in origins if enabled.get(x["module"], False)]
    if origins:
        return tr(cfg["language"], "event_drop", proto=values.get("PROTO", "IP"), src=src,
                  categories=", ".join(sorted({x["module"] for x in origins})),
                  sources=", ".join(sorted({x["source"] for x in origins})), generation=generation["id"])
    if "NEXTGUARD_PING" in line and enabled.get("ping"):
        return tr(cfg["language"], "event_ping", src=src, generation=generation.get("id", "-"))
    return None


def main() -> int:
    EVENT_LOG.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    process = subprocess.Popen(["journalctl", "-k", "-f", "-n", "0", "-o", "cat"], stdout=subprocess.PIPE, text=True)
    recent: collections.OrderedDict[str, float] = collections.OrderedDict()
    assert process.stdout
    generation, index, loaded_id = {"id": "-", "provenance": {}}, {}, None
    for line in process.stdout:
        if "NEXTGUARD_" not in line:
            continue
        try:
            cfg = load()
            current_id = CURRENT.resolve().name if CURRENT.exists() else None
            if current_id != loaded_id:
                generation = json.loads((CURRENT / "generation.json").read_text()) if current_id else {"id": "-", "provenance": {}}
                index, loaded_id = build_index(generation), current_id
            message = format_event(line, cfg, generation, index)
            if not message:
                continue
            stamp = dt.datetime.now().astimezone().isoformat(timespec="seconds")
            key = message
            moment = dt.datetime.now().timestamp()
            if moment - recent.get(key, 0) < 5:
                continue
            recent[key] = moment
            while len(recent) > 2048:
                recent.popitem(last=False)
            rotate(EVENT_LOG)
            with EVENT_LOG.open("a", encoding="utf-8") as output:
                output.write(f"{stamp} {message}\n")
            print(message, flush=True)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"NextGuard log processing error: {exc}", flush=True)
    return process.wait()
