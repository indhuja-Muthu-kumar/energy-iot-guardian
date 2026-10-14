from __future__ import annotations

import json
from pathlib import Path


DATA_FILE = Path(__file__).resolve().parents[1] / "data" / "vendor_aliases.json"


def load_vendor_aliases() -> dict[str, str]:
    if not DATA_FILE.exists():
        return {}
    with DATA_FILE.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def resolve_vendor_token(vendor_name: str) -> str:
    aliases = load_vendor_aliases()
    normalized = vendor_name.strip().lower()
    for name, token in aliases.items():
        if normalized == name.strip().lower():
            return token.lower()
    return normalized.replace(" ", "")
