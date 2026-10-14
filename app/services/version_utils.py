from __future__ import annotations

import re


def normalize_version(value: str | None) -> str:
    if not value:
        return "0"
    cleaned = re.sub(r"[^0-9A-Za-z.+_-]", "", str(value))
    cleaned = cleaned.lstrip("vV")
    return cleaned or "0"


def parse_version(value: str | None) -> list[int]:
    text = normalize_version(value)
    parts = re.findall(r"\d+", text)
    return [int(part) for part in parts] or [0]


def compare_versions(left: str | None, right: str | None) -> int:
    a = parse_version(left)
    b = parse_version(right)
    max_len = max(len(a), len(b))
    a += [0] * (max_len - len(a))
    b += [0] * (max_len - len(b))
    if a < b:
        return -1
    if a > b:
        return 1
    return 0
