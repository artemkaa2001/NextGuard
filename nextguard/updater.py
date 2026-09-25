from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import json
import os
import shutil
import tempfile
import time
import urllib.error
import urllib.request
from email.utils import parsedate_to_datetime
from pathlib import Path

from .config import atomic_json, load
from .firewall import apply
from .parsers import PARSERS, collapse_exact
from .paths import CACHE, CURRENT, GENERATIONS, LOCK, SOURCES_CONFIG, STATE

MAX_BYTES = 32 * 1024 * 1024


class RateLimitError(RuntimeError):
    def __init__(self, retry_after: str | None):
        super().__init__("HTTP 429" + (f"; Retry-After={retry_after}" if retry_after else ""))
        self.retry_after = retry_after


def retry_epoch(value: str | None) -> float:
    if not value:
        return time.time() + 3600
    try:
        return time.time() + max(0, int(value))
    except ValueError:
        try:
            return parsedate_to_datetime(value).timestamp()
        except (TypeError, ValueError, OverflowError):
            return time.time() + 3600


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def source_catalog() -> list[dict]:
    return json.loads(SOURCES_CONFIG.read_text(encoding="utf-8"))["sources"]


def _read_response(response) -> bytes:
    length = response.headers.get("Content-Length")
    if length and int(length) > MAX_BYTES:
        raise ValueError("response exceeds 32 MiB")
    chunks, total = [], 0
    while chunk := response.read(65536):
        total += len(chunk)
        if total > MAX_BYTES:
            raise ValueError("response exceeds 32 MiB")
        chunks.append(chunk)
    return b"".join(chunks)


def fetch(source: dict, cache: Path, opener=urllib.request.urlopen) -> tuple[bytes | None, dict]:
    meta_path = cache / "metadata.json"
    old = json.loads(meta_path.read_text()) if meta_path.exists() else {}
    if old.get("retry_after_epoch", 0) > time.time():
        return None, {**old, "deferred": True}
    minimum = int(source.get("minimum_interval_minutes", 0)) * 60
    if old.get("last_attempt_epoch") and time.time() - old["last_attempt_epoch"] < minimum:
        return None, old
    headers = {"User-Agent": "NextGuard/1.0 (+local firewall updater)", "Accept": "text/plain, application/json"}
    if old.get("etag"):
        headers["If-None-Match"] = old["etag"]
    if old.get("last_modified"):
        headers["If-Modified-Since"] = old["last_modified"]
    request = urllib.request.Request(source["url"], headers=headers)
    attempted = {**old, "last_attempt": now(), "last_attempt_epoch": time.time()}
    try:
        response = opener(request, timeout=30)
        with response:
            data = _read_response(response)
            attempted.update(etag=response.headers.get("ETag"), last_modified=response.headers.get("Last-Modified"))
            return data, attempted
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            if not (cache / "raw").exists():
                raise RuntimeError("HTTP 304 without a cached copy") from exc
            return None, attempted
        if exc.code == 429:
            raise RateLimitError(exc.headers.get("Retry-After")) from exc
        raise RuntimeError(f"HTTP {exc.code}") from exc


def update_source(source: dict, opener=urllib.request.urlopen) -> dict:
    cache = CACHE / source["id"]
    cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    meta_path, raw_path, nets_path = cache / "metadata.json", cache / "raw", cache / "networks.json"
    old = json.loads(meta_path.read_text()) if meta_path.exists() else {}
    try:
        data, meta = fetch(source, cache, opener)
        if data is None:
            if not nets_path.exists():
                raise RuntimeError("no validated cached copy")
            if not meta.pop("deferred", False):
                meta.update(error=None)
            atomic_json(meta_path, meta)
            return meta
        networks, ipv6, extra = PARSERS[source["adapter"]](data, allow_empty=source.get("allow_empty", False))
        normalized = sorted({str(x) for x in networks})
        digest = hashlib.sha256(data).hexdigest()
        fd, temporary = tempfile.mkstemp(dir=cache, prefix=".raw.")
        with os.fdopen(fd, "wb") as output:
            output.write(data); output.flush(); os.fsync(output.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, raw_path)
        atomic_json(nets_path, {"networks": normalized, "metadata": extra})
        changed = digest != old.get("sha256")
        meta.update(error=None, sha256=digest, ipv4_count=len(normalized), ipv6_skipped=ipv6,
                    last_success=now(), last_changed=now() if changed else old.get("last_changed", now()))
        atomic_json(meta_path, meta)
        return meta
    except Exception as exc:
        meta = {**old, "last_attempt": now(), "last_attempt_epoch": time.time(), "error": str(exc)}
        if isinstance(exc, RateLimitError):
            meta.update(retry_after=exc.retry_after, retry_after_epoch=retry_epoch(exc.retry_after))
        atomic_json(meta_path, meta)
        return meta


def build_generation(cfg: dict, catalog: list[dict]) -> dict:
    provenance: dict[str, list[dict]] = {}
    all_networks = []
    for source in catalog:
        if not cfg["modules"].get(source["module"], False):
            continue
        path = CACHE / source["id"] / "networks.json"
        if not path.exists():
            continue
        for network in json.loads(path.read_text())["networks"]:
            all_networks.append(__import__("ipaddress").ip_network(network))
            provenance.setdefault(network, []).append({"source": source["id"], "module": source["module"], "organization": source.get("organization")})
    collapsed = [str(x) for x in collapse_exact(all_networks)]
    return {"id": dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ"), "created": now(),
            "networks": collapsed, "provenance": provenance, "interfaces": cfg["interfaces"],
            "logging_enabled": any(cfg["logging"].values())}


def perform(*, download: bool = True) -> dict:
    LOCK.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    with LOCK.open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        cfg, catalog = load(), source_catalog()
        metadata = [update_source(s) for s in catalog if download and cfg["modules"].get(s["module"])]
        generation = build_generation(cfg, catalog)
        GENERATIONS.mkdir(parents=True, exist_ok=True, mode=0o700)
        staging = GENERATIONS / ("." + generation["id"])
        staging.mkdir(mode=0o700)
        atomic_json(staging / "generation.json", generation)
        apply(generation["networks"], generation["logging_enabled"], generation["interfaces"])
        final = GENERATIONS / generation["id"]
        os.replace(staging, final)
        temporary_link = STATE / ".current"
        temporary_link.unlink(missing_ok=True)
        temporary_link.symlink_to(Path("generations") / final.name)
        os.replace(temporary_link, CURRENT)
        keep = sorted((p for p in GENERATIONS.iterdir() if p.is_dir() and not p.name.startswith(".")), reverse=True)
        for obsolete in keep[2:]:
            shutil.rmtree(obsolete)
        return {"generation": generation, "failed": sum(bool(x.get("error")) for x in metadata)}
