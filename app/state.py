# app/state.py
import os, json
from pathlib import Path
from typing import Any

STATE_FILE = os.getenv("STATE_FILE", "./data/delta_state.json")

def _ensure_dir():
    Path(STATE_FILE).parent.mkdir(parents=True, exist_ok=True)

def load_state() -> dict[str, Any]:
    _ensure_dir()
    if not Path(STATE_FILE).exists():
        return {}
    try:
        return json.loads(Path(STATE_FILE).read_text("utf-8"))
    except Exception:
        return {}

def save_state(state: dict[str, Any]) -> None:
    _ensure_dir()
    Path(STATE_FILE).write_text(json.dumps(state, indent=2), encoding="utf-8")

def get_delta_link(group_id: str) -> str | None:
    state = load_state()
    return (state.get("groups") or {}).get(group_id, {}).get("deltaLink")

def set_delta_link(group_id: str, delta_link: str) -> None:
    state = load_state()
    groups = state.setdefault("groups", {})
    entry = groups.setdefault(group_id, {})
    entry["deltaLink"] = delta_link
    save_state(state)
