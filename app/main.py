# app/main.py
import os
import re
import json
import html
import httpx
import logging
import pathlib
import hashlib
from collections import deque
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List, Tuple

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse, Response, PlainTextResponse, HTMLResponse
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="Azure AD Webhook + Graph POC")
logger = logging.getLogger("uvicorn")

# --- Config ---
CLIENT_STATE = (os.getenv("CLIENT_STATE") or "").strip()
NOTIFICATION_URL = os.getenv("NOTIFICATION_URL") or ""

TENANT_ID = os.getenv("TENANT_ID") or ""
CLIENT_ID = os.getenv("CLIENT_ID") or ""
CLIENT_SECRET = os.getenv("CLIENT_SECRET") or ""
GRAPH_BASE = "https://graph.microsoft.com/v1.0"
AUTH_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"

_GROUP_IDS_RAW = (os.getenv("GROUP_IDS") or "").strip()
GROUP_IDS = [g.strip() for g in _GROUP_IDS_RAW.split(",") if g.strip()]
GROUP_ID = (os.getenv("GROUP_ID") or "").strip()
if not GROUP_IDS and GROUP_ID:
    GROUP_IDS = [GROUP_ID]

def _is_allowed_group(gid: Optional[str]) -> bool:
    if not gid:
        return False
    return any(gid.lower() == g.lower() for g in GROUP_IDS)

# --- In-memory state + simple file log ---
LAST_VALIDATION: Optional[Dict[str, Any]] = None
LAST_POST: Optional[Dict[str, Any]] = None

EVENTS: List[Dict[str, Any]] = []
LOG_PATH = pathlib.Path("/tmp/graph_notifications.jsonl")

LOG_INCLUDE_VALIDATIONS = (os.getenv("LOG_INCLUDE_VALIDATIONS", "false").lower() == "true")
LOG_DEDUP_WINDOW = int(os.getenv("LOG_DEDUP_WINDOW", "300"))  # seconds to keep recent keys for dedup
_RECENT_KEYS: deque[tuple[str, float]] = deque(maxlen=500)  # (key, ts)

# Per-group delta cursor storage
DELTA_STATE_FILE = pathlib.Path("/tmp/members_delta_state.json")

# --- Small helpers ---
def _mask(v: str) -> str:
    return f"{v[:4]}…{v[-4:]}" if v and len(v) > 8 else v or "(empty)"

def _ok(msg: str, **extra):
    return {"status": "OK", "message": msg, **extra}

def _now_iso():
    return datetime.now(timezone.utc).isoformat()

def _append_event(kind: str, data: Dict[str, Any]):
    event = {"ts": _now_iso(), "kind": kind, **data}
    EVENTS.append(event)
    try:
        with LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    except Exception as e:
        logger.warning(f"[log] failed to write {LOG_PATH}: {e}")

def _load_events_from_disk():
    if LOG_PATH.exists() and not EVENTS:
        try:
            with LOG_PATH.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    EVENTS.append(json.loads(line))
        except Exception as e:
            logger.warning(f"[log] failed to read {LOG_PATH}: {e}")

def _hash_obj(o: Any) -> str:
    j = json.dumps(o, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(j.encode("utf-8")).hexdigest()

def _seen_recent(key: str) -> bool:
    now = datetime.now(timezone.utc).timestamp()
    while _RECENT_KEYS and (now - _RECENT_KEYS[0][1]) > LOG_DEDUP_WINDOW:
        _RECENT_KEYS.popleft()
    for k, _ts in _RECENT_KEYS:
        if k == key:
            return True
    _RECENT_KEYS.append((key, now))
    return False

def _render_html_log() -> str:
    _load_events_from_disk()
    rows = []
    for ev in reversed(EVENTS):
        kind = html.escape(ev.get("kind", ""))
        ts = html.escape(ev.get("ts", ""))
        ip = html.escape(str(ev.get("client_ip", "")))
        summary = html.escape(ev.get("summary", "") or "")
        raw = ev.get("raw")
        if raw is None and "body" in ev:
            raw = ev["body"]
        raw_pretty = html.escape(json.dumps(raw, indent=2, ensure_ascii=False)) if raw is not None else ""
        meta = ev.copy()
        for k in ("raw", "body"):
            meta.pop(k, None)
        meta_pretty = html.escape(json.dumps(meta, indent=2, ensure_ascii=False))

        rows.append(f"""
        <article style="border:1px solid #e5e7eb; border-radius:12px; padding:12px; margin:10px 0;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <h3 style="margin:0;font-family:system-ui,Segoe UI,Roboto;">{kind}</h3>
            <div style="color:#6b7280;font-size:12px;">{ts} · {ip}</div>
          </div>
          <div style="margin:6px 0; font-weight:600;">{summary}</div>
          <details>
            <summary style="cursor:pointer;">Raw payload</summary>
            <pre style="white-space:pre-wrap; background:#0b1020; color:#d1e7ff; padding:10px; border-radius:8px; overflow:auto; font-size:12px;">{raw_pretty}</pre>
          </details>
          <details>
            <summary style="cursor:pointer;">Meta</summary>
            <pre style="white-space:pre-wrap; background:#111827; color:#e5e7eb; padding:10px; border-radius:8px; overflow:auto; font-size:12px;">{meta_pretty}</pre>
          </details>
        </article>
        """)
    body = "\n".join(rows) or "<p>No events yet.</p>"

    footer_text = "Auto-refresh off (press ⟳)"

    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Graph Notifications Log</title>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
</head>
<body style="margin:0; background:#f9fafb;">
<header style="position:sticky; top:0; background:white; border-bottom:1px solid #e5e7eb; padding:12px;">
  <div style="max-width:1000px; margin:0 auto; display:flex; justify-content:space-between; align-items:center;">
    <h1 style="margin:0; font-family:system-ui,Segoe UI,Roboto; font-size:18px;">Graph Notifications Log</h1>
    <form method="post" action="/notifications/log/clear" onsubmit="return confirm('Clear the log?');">
      <button type="submit" style="padding:8px 12px; border:1px solid #ef4444; color:#ef4444; border-radius:8px; background:white;">Clear</button>
    </form>
  </div>
</header>
<main style="max-width:1000px; margin:0 auto; padding:12px;">
  {body}
</main>
<footer style="text-align:center; color:#6b7280; padding:20px;">{footer_text}</footer>
</body>
</html>"""

# --- Graph helpers ---
async def _get_graph_token() -> str:
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.post(
            AUTH_URL,
            data={
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "grant_type": "client_credentials",
                "scope": "https://graph.microsoft.com/.default",
            },
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

def _load_delta_state() -> Dict[str, Any]:
    try:
        if DELTA_STATE_FILE.exists():
            return json.loads(DELTA_STATE_FILE.read_text(encoding="utf-8"))
    except Exception as e:
        logger.warning(f"[delta] load failed: {e}")
    return {}

def _save_delta_state(state: Dict[str, Any]) -> None:
    try:
        DELTA_STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as e:
        logger.warning(f"[delta] save failed: {e}")

async def _members_delta_once(group_id: str) -> Dict[str, list]:
    """
    One delta sweep for the group's direct members.
    Returns {'added': [userIds], 'removed': [userIds]} and stores deltaLink for next time.
    The very first call (no prior deltaLink) returns a baseline (no adds/removes).
    """
    state = _load_delta_state()
    prev = state.get(group_id, {}).get("deltaLink")

    token = await _get_graph_token()
    # Using members delta for direct membership tracking.
    url = prev or f"{GRAPH_BASE}/groups/{group_id}/members/delta?$select=id&$top=999"

    added, removed = set(), set()
    async with httpx.AsyncClient(timeout=30) as client:
        while True:
            r = await client.get(url, headers={"Authorization": f"Bearer {token}"})
            r.raise_for_status()
            data = r.json()

            for item in data.get("value", []):
                oid = item.get("id")
                if not oid:
                    continue
                if "@removed" in item:
                    removed.add(oid)
                else:
                    added.add(oid)

            nxt = data.get("@odata.nextLink")
            if nxt:
                url = nxt
                continue

            dl = data.get("@odata.deltaLink")
            if dl:
                state[group_id] = {"deltaLink": dl, "ts": _now_iso()}
                _save_delta_state(state)
            break

    return {"added": sorted(added), "removed": sorted(removed)}

# --- Routing ---
@app.get("/")
async def root():
    return _ok(
        "API running",
        notification_url=NOTIFICATION_URL,
        tenant_masked=_mask(os.getenv("TENANT_ID") or ""),
        client_masked=_mask(os.getenv("CLIENT_ID") or ""),
        group_ids=GROUP_IDS or ["(not set)"]
    )

@app.get("/api/graph/diag")
async def graph_diag():
    diag = {
        "tenant_present": bool(os.getenv("TENANT_ID")),
        "client_present": bool(os.getenv("CLIENT_ID")),
        "secret_present": bool(os.getenv("CLIENT_SECRET")),
        "tenant_masked": _mask(os.getenv("TENANT_ID") or ""),
        "client_masked": _mask(os.getenv("CLIENT_ID") or ""),
        "group_ids": GROUP_IDS or ["(not set)"],
    }
    if not (TENANT_ID and CLIENT_ID and CLIENT_SECRET):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"status": "ERROR", "message": "Missing required environment variables", **diag},
        )
    return JSONResponse(status_code=200, content={"status": "OK", "message": "Graph creds present", **diag})

# Validation echo (GET)
@app.get("/notifications")
async def validate(request: Request, validationToken: Optional[str] = None):
    global LAST_VALIDATION
    if validationToken:
        info = {
            "when": _now_iso(),
            "token_len": len(validationToken),
            "client_ip": request.client.host if request.client else None,
            "headers": dict(request.headers),
            "note": "Graph validation GET received",
        }
        LAST_VALIDATION = info
        logger.info(f"[validation-get] {info}")
        if LOG_INCLUDE_VALIDATIONS:
            _append_event("validation-get", {"client_ip": info["client_ip"], "summary": "GET validation", "raw": {"validationToken": validationToken}, **info})
        return PlainTextResponse(validationToken, status_code=200)
    return Response(status_code=204)

# Parse resource like:
#   Groups/{G}/members
#   Groups/{G}/members/{U}
#   Groups/{G}/members/$ref
def _parse_resource(res: str) -> Tuple[Optional[str], Optional[str]]:
    if not res:
        return None, None
    m = re.match(
        r"^/?[Gg]roups/([0-9a-fA-F-]{36})/members(?:/([0-9a-fA-F-]{36}))?(?:/\$ref)?(?:$|/)",
        res,
    )
    if m:
        gid = m.group(1)
        uid = m.group(2) if len(m.groups()) >= 2 else None
        return gid, uid
    return None, None

def _fmt_user(u: Dict[str, Any]) -> str:
    name = u.get("displayName") or u.get("userPrincipalName") or u.get("id")
    email = u.get("emailResolved") or u.get("mail") or u.get("userPrincipalName") or "-"
    return f"{name} <{email}>"

def _is_removed_marker(v: Any) -> bool:
    if v is None:
        return False
    if isinstance(v, str):
        return v.lower() == "deleted"
    if isinstance(v, dict):
        return (v.get("reason") or "").lower() == "deleted"
    return False

# Notification receiver (POST)
@app.post("/notifications")
async def notifications(request: Request):
    global LAST_POST, LAST_VALIDATION

    # POST validation echo support (some hosts route validation as POST)
    token = request.query_params.get("validationToken")
    if token:
        info = {
            "when": _now_iso(),
            "token_len": len(token),
            "client_ip": request.client.host if request.client else None,
            "headers": dict(request.headers),
            "note": "Graph validation POST received",
        }
        LAST_VALIDATION = info
        logger.info(f"[validation-post] {info}")
        if LOG_INCLUDE_VALIDATIONS:
            _append_event("validation-post", {"client_ip": info["client_ip"], "summary": "POST validation", "raw": {"validationToken": token}, **info})
        return PlainTextResponse(token, status_code=200)

    # Parse body
    try:
        body = await request.json()
    except Exception:
        LAST_POST = {"when": _now_iso(), "error": "invalid_json"}
        return JSONResponse({"error": "invalid_json"}, status_code=400)

    value = body.get("value") or []
    if not isinstance(value, list):
        LAST_POST = {"when": _now_iso(), "error": "bad_payload", "raw": body}
        return JSONResponse({"error": "bad_payload"}, status_code=400)

    # Verify clientState if provided
    for n in value:
        incoming = (n.get("clientState") or "").strip()
        if CLIENT_STATE and incoming and incoming != CLIENT_STATE:
            LAST_POST = {"when": _now_iso(), "error": "client_state_mismatch", "raw": value}
            return JSONResponse({"error": "client_state_mismatch"}, status_code=403)

    user_ops: List[Dict[str, Any]] = []
    touched_groups: set[str] = set()

    # Interpret notifications
    for n in value:
        res = (n.get("resource") or "").strip()
        change = (n.get("changeType") or "").strip().lower()

        g_id, u_id = _parse_resource(res)
        if not g_id or not _is_allowed_group(g_id):
            continue

        # If Graph included a userId in the resource path (rare), we can enrich immediately
        if u_id:
            action = "added" if change == "created" else "removed" if change == "deleted" else "updated"
            try:
                token = await _get_graph_token()
                async with httpx.AsyncClient(timeout=20) as client:
                    r = await client.get(
                        f"{GRAPH_BASE}/users/{u_id}?$select=id,displayName,mail,userPrincipalName,otherMails,proxyAddresses",
                        headers={"Authorization": f"Bearer {token}"}
                    )
                    u = r.json() if r.status_code == 200 else {"id": u_id}
            except Exception:
                u = {"id": u_id}
            # minimal format; email resolution optional
            user_ops.append({
                "action": action,
                "relation": "members",
                "user": {
                    "id": u.get("id"),
                    "displayName": u.get("displayName"),
                    "mail": u.get("mail"),
                    "userPrincipalName": u.get("userPrincipalName"),
                },
                "sourceChangeType": change or None,
                "resource": res,
            })
        else:
            # Typical case: /members or /members/$ref — mark group for delta sweep
            touched_groups.add(g_id)

    # Resolve who changed via members delta (direct membership)
    if touched_groups:
        try:
            for tg in list(touched_groups)[:10]:  # cap to be safe
                delta = await _members_delta_once(tg)
                for uid in delta["added"][:50]:
                    user_ops.append({"action": "added", "relation": "members", "user": {"id": uid}, "sourceChangeType": "updated", "resource": f"Groups/{tg}"})
                for uid in delta["removed"][:50]:
                    user_ops.append({"action": "removed", "relation": "members", "user": {"id": uid}, "sourceChangeType": "updated", "resource": f"Groups/{tg}"})
        except Exception as e:
            logger.warning(f"[delta] sweep failed: {e}")

    if not user_ops and not touched_groups:
        return JSONResponse(status_code=200, content=_ok("no-op (ignored non-target group or no member info)"))

    # Dedup close duplicates to reduce noise
    dedup_key = _hash_obj({
        "gids": sorted(GROUP_IDS),
        "ops": [{"a": op["action"], "id": (op.get("user") or {}).get("id"), "res": op.get("resource")} for op in user_ops]
    })
    if _seen_recent(dedup_key):
        return JSONResponse(status_code=200, content=_ok("duplicate notification (suppressed)"))

    # Summary line for UI
    added = [op for op in user_ops if op["action"] == "added"]
    removed = [op for op in user_ops if op["action"] == "removed"]

    parts = [f"{len(value)} notification(s)"]
    if touched_groups:
        parts.append("groups: " + ", ".join(sorted(touched_groups)))
    if added:
        parts.append("added: " + "; ".join(op["user"]["id"] for op in added))
    if removed:
        parts.append("removed: " + "; ".join(op["user"]["id"] for op in removed))

    info = {
        "when": _now_iso(),
        "client_ip": request.client.host if request.client else None,
        "count": len(value),
        "group_ids": GROUP_IDS,
        "ops": user_ops,          # normalized operations list
        "raw": value,             # full incoming body.value for troubleshooting
        "summary": " | ".join(parts),
    }
    LAST_POST = info
    logger.info(f"[notification] {info}")
    _append_event("notification", info)

    return JSONResponse(status_code=200, content=_ok("notification received", **info))

@app.get("/notifications/debug")
async def notifications_debug():
    _load_events_from_disk()
    processed = [e for e in EVENTS if e.get("kind") == "notification"]
    return {
        "last_validation": LAST_VALIDATION,
        "last_post": LAST_POST,
        "recent_notifications": processed[-50:],
    }

@app.get("/notifications/log")
async def notifications_log():
    return HTMLResponse(_render_html_log(), status_code=200)

@app.post("/notifications/log/clear")
async def notifications_log_clear():
    EVENTS.clear()
    try:
        if LOG_PATH.exists():
            LOG_PATH.unlink()
    except Exception as e:
        logger.warning(f"[log] failed to clear {LOG_PATH}: {e}")
    return HTMLResponse(_render_html_log(), status_code=200)
