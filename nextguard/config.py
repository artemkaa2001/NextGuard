from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from .paths import CONFIG

DEFAULT = {
    "schema": 1,
    "configured": False,
    "language": "ru",
    "interval_minutes": 60,
    "modules": {"rkn": False, "attackers": False, "scanners": False, "ping": False},
    "logging": {"rkn": True, "attackers": True, "scanners": True, "ping": True},
    "interfaces": [],
}


def atomic_json(path: Path, value: object, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def load(path: Path = CONFIG) -> dict:
    cfg = json.loads(json.dumps(DEFAULT))
    if path.exists():
        supplied = json.loads(path.read_text(encoding="utf-8"))
        for key in ("configured", "language", "interval_minutes", "interfaces"):
            if key in supplied:
                cfg[key] = supplied[key]
        for group in ("modules", "logging"):
            cfg[group].update(supplied.get(group, {}))
    validate(cfg)
    return cfg


def validate(cfg: dict) -> None:
    if cfg["language"] not in {"ru", "en"}:
        raise ValueError("language must be ru or en")
    if cfg["interval_minutes"] not in {30, 60}:
        raise ValueError("interval_minutes must be 30 or 60")
    if not isinstance(cfg["interfaces"], list) or any(not isinstance(x, str) or not x for x in cfg["interfaces"]):
        raise ValueError("interfaces must be a list of names")
    for group in ("modules", "logging"):
        if any(not isinstance(v, bool) for v in cfg[group].values()):
            raise ValueError(f"{group} values must be boolean")
