from __future__ import annotations

import os
from pathlib import Path

PREFIX = Path(os.environ.get("NEXTGUARD_PREFIX", "/"))


def rooted(path: str) -> Path:
    return PREFIX / path.lstrip("/")


CONFIG = rooted("/etc/nextguard/config.json")
SOURCES_CONFIG = rooted("/etc/nextguard/sources.json")
STATE = rooted("/var/lib/nextguard")
CACHE = STATE / "sources"
GENERATIONS = STATE / "generations"
CURRENT = STATE / "current"
RUN = rooted("/run/nextguard")
LOCK = RUN / "update.lock"
EVENT_LOG = rooted("/var/log/nextguard/events.log")
SERVICE_LOG = rooted("/var/log/nextguard/service.log")
