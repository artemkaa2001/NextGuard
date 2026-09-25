from __future__ import annotations

import ipaddress
import json
import re


class ParseError(ValueError):
    pass


def _network(token: str) -> tuple[ipaddress.IPv4Network | None, bool]:
    try:
        value = ipaddress.ip_network(token.strip(), strict=False)
    except ValueError as exc:
        raise ParseError(f"invalid address: {token}") from exc
    if value.version == 6:
        return None, True
    if value.prefixlen == 0:
        raise ParseError("0.0.0.0/0 is forbidden")
    return value, False


def parse_lines(data: bytes, *, allow_empty: bool = False) -> tuple[list[ipaddress.IPv4Network], int, dict]:
    text = decode(data)
    networks, ipv6 = [], 0
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        token = line.split()[0]
        try:
            net, is_v6 = _network(token)
        except ParseError as exc:
            raise ParseError(f"line {number}: {exc}") from exc
        ipv6 += int(is_v6)
        if net:
            networks.append(net)
    if not networks and not allow_empty:
        raise ParseError("unexpected empty list")
    return networks, ipv6, {}


def parse_ipsum(data: bytes, *, allow_empty: bool = False):
    nets, ipv6, metadata = parse_lines(data, allow_empty=allow_empty)
    counts = {}
    for raw in decode(data).splitlines():
        parts = raw.split()
        if parts and not parts[0].startswith("#") and len(parts) > 1 and parts[1].isdigit():
            counts[parts[0]] = int(parts[1])
    metadata["counts"] = counts
    return nets, ipv6, metadata


def parse_dshield(data: bytes, *, allow_empty: bool = False):
    text = decode(data)
    networks, ipv6 = [], 0
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("Start"):
            continue
        parts = re.split(r"\s+", line)
        if len(parts) < 3:
            raise ParseError(f"line {number}: malformed DShield row")
        try:
            start = ipaddress.ip_address(parts[0])
            count = int(parts[2])
            end = start + count - 1
        except (ValueError, TypeError) as exc:
            raise ParseError(f"line {number}: malformed DShield range") from exc
        if start.version == 6:
            ipv6 += 1
            continue
        if count < 1:
            raise ParseError(f"line {number}: invalid address count")
        networks.extend(ipaddress.summarize_address_range(start, end))
    if not networks and not allow_empty:
        raise ParseError("unexpected empty list")
    return networks, ipv6, {}


def parse_spamhaus(data: bytes, *, allow_empty: bool = False):
    text = decode(data)
    networks, ipv6 = [], 0
    try:
        obj = json.loads(text)
        if isinstance(obj, list):
            rows = obj
        elif isinstance(obj, dict) and ("cidr" in obj or "network" in obj):
            rows = [obj]
        elif isinstance(obj, dict):
            rows = obj.get("records", obj.get("data", []))
        else:
            raise ParseError("invalid Spamhaus document")
    except json.JSONDecodeError:
        rows = []
        for number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ParseError(f"line {number}: invalid JSON") from exc
    if not isinstance(rows, list):
        raise ParseError("invalid Spamhaus document")
    for row in rows:
        if not isinstance(row, dict):
            raise ParseError("invalid Spamhaus record")
        token = row.get("cidr") or row.get("network")
        if not token:  # published metadata/terms records
            continue
        net, is_v6 = _network(str(token))
        ipv6 += int(is_v6)
        if net:
            networks.append(net)
    if not networks and not allow_empty:
        raise ParseError("unexpected empty list")
    return networks, ipv6, {}


def decode(data: bytes) -> str:
    if not data or data.lstrip().lower().startswith((b"<!doctype html", b"<html")):
        raise ParseError("empty or HTML response")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ParseError("response is not UTF-8") from exc


PARSERS = {"lines": parse_lines, "ipsum": parse_ipsum, "dshield": parse_dshield, "spamhaus": parse_spamhaus}


def collapse_exact(networks):
    """Collapse only adjacent/already-contained networks; never broadens membership."""
    return list(ipaddress.collapse_addresses(networks))
