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
from typing import Any, Dict, Optional, List

from fastapi import FastAPI, Request, status, Form
from fastapi.responses import JSONResponse, Response, PlainTextResponse, HTMLResponse
from dotenv import load_dotenv

# Load .env once at startup
load_dotenv()

# local imports after dotenv so env is available
from app import graph as g  # noqa: E402

app = FastAPI(title="Azure AD Webhook + Graph POC")
logger = logging.getLogger("uvicorn")

CLIENT_STATE = (os.getenv("CLIENT_STATE") or "").strip()
NOTIFICATION_URL = os.getenv("NOTIFICATION_URL") or ""

# ---- new: graph app creds for lookup ----
TENANT_ID = os.getenv("TENANT_ID") or ""
CLIENT_ID = os.getenv("CLIENT_ID") or ""
CLIENT_SECRET = os.getenv("CLIENT_SECRET") or ""
GRAPH_BASE = "https://graph.microsoft.com/v1.0"
AUTH_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"

# ---- lightweight in-app debug state ----
LAST_VALIDATION: Optional[Dict[str, Any]] = None
LAST_POST: Optional[Dict[str, Any]] = None

# ---- new: persistent event log (memory + file) ----
EVENTS: List[Dict[str, Any]] = []
LOG_PATH = pathlib.Path("/tmp/graph_notifications.jsonl")

# ---- log behavior toggles ----
LOG_AUTO_REFRESH_SECS = int(os.getenv("LOG_AUTO_REFRESH_SECS", "0"))  # 0 = no auto-refresh
LOG_INCLUDE_VALIDATIONS = (os.getenv("LOG_INCLUDE_VALIDATIONS", "false").lower() == "true")
LOG_DEDUP_WINDOW = int(os.getenv("LOG_DEDUP_WINDOW", "300"))  # seconds to keep recent keys for dedup

# ---- dedup state ----
_RECENT_KEYS: deque[tuple[str, float]] = deque(maxlen=500)  # (key, ts)


def _mask(v: str) -> str:
    return f"{v[:4]}…{v[-4:]}" if v and len(v) > 8 else v or "(empty)"


def _ok(msg: str, **extra):
    return {"status": "OK", "message": msg, **extra}


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _append_event(kind: str, data: Dict[str, Any]):
    event = {
        "ts": _now_iso(),
        "kind": kind,
        **data,
    }
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
    # stable hash of the interesting payload (sort keys to normalize)
    j = json.dumps(o, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(j.encode("utf-8")).hexdigest()


def _seen_recent(key: str) -> bool:
    now = datetime.now(timezone.utc).timestamp()
    # prune expired
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
            <div style="color:#6b7280;font-size:12px;">{ts} &middot; {ip}</div>
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

    refresh_tag = f'<meta http-equiv="refresh" content="{LOG_AUTO_REFRESH_SECS}" />' if LOG_AUTO_REFRESH_SECS > 0 else ""
    footer_text = f"Auto-refreshing every {LOG_AUTO_REFRESH_SECS}s" if LOG_AUTO_REFRESH_SECS > 0 else "Auto-refresh off (press ⟳)"

    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  {refresh_tag}
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


# ---- new: minimal Graph helper (app-only) ----
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


async def _get_user_basic(user_id: str) -> Optional[Dict[str, Any]]:
    token = await _get_graph_token()
    url = f"{GRAPH_BASE}/users/{user_id}?$select=id,displayName,mail,userPrincipalName"
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(url, headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 404:
            return None
        r.raise_for_status()
        u = r.json()
        return {
            "id": u.get("id"),
            "displayName": u.get("displayName"),
            "mail": u.get("mail"),
            "userPrincipalName": u.get("userPrincipalName"),
        }

# --- membership delta helpers (persist deltaLink so next call is incremental) ---
DELTA_STATE_FILE = pathlib.Path("/tmp/members_delta_state.json")

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
    One delta sweep for the group's members.
    Returns {'added': [userIds], 'removed': [userIds]} and stores deltaLink for next time.
    """
    state = _load_delta_state()
    prev = state.get(group_id, {}).get("deltaLink")

    token = await _get_graph_token()
    # Only fetch ids here; we expand to names/emails via _get_user_basic()
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


# ------------------------
# Basic health
# ------------------------
@app.get("/")
async def root():
    return _ok(
        "API running",
        notification_url=NOTIFICATION_URL,
        tenant_masked=_mask(os.getenv("TENANT_ID") or ""),
        client_masked=_mask(os.getenv("CLIENT_ID") or ""),
    )


# ------------------------
# URL #1: Graph connectivity diagnostic
# ------------------------
@app.get("/api/graph/diag")
async def graph_diag(raw: int = 0):
    diag = {
        "tenant_present": bool(os.getenv("TENANT_ID")),
        "client_present": bool(os.getenv("CLIENT_ID")),
        "secret_present": bool(os.getenv("CLIENT_SECRET")),
        "tenant_masked": _mask(os.getenv("TENANT_ID") or ""),
        "client_masked": _mask(os.getenv("CLIENT_ID") or ""),
    }

    missing = [k for k in ("TENANT_ID", "CLIENT_ID", "CLIENT_SECRET") if not os.getenv(k)]
    if missing:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"status": "ERROR", "message": "Missing required environment variables", "missing": missing, **diag},
        )

    try:
        user = g.diag_first_user()
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"status": "OK", "message": "Graph reachable", "saw_user": bool(user), "sample_user": user, **diag},
        )

    except httpx.HTTPStatusError as e:
        body_text = e.response.text if raw else (e.response.text[:1500] + ("…(truncated)" if len(e.response.text) > 1500 else ""))
        hint = None
        if e.response.status_code == 403:
            hint = (
                "403 Forbidden from Graph. For app-only calls to /users, grant Microsoft Graph "
                "Application permissions (User.Read.All, Group.Read.All; often Directory.Read.All) "
                "and click 'Grant admin consent' in Azure Portal."
            )
        elif e.response.status_code == 401:
            hint = "401 Unauthorized. Check CLIENT_ID/CLIENT_SECRET, tenant, and that the secret hasn't expired."

        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content={
                "status": "ERROR",
                "message": "Microsoft Graph returned an error",
                "error": {"status_code": e.response.status_code, "url": str(e.request.url), "body": body_text},
                "hint": hint,
                **diag,
            },
        )

    except httpx.RequestError as e:
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content={
                "status": "ERROR",
                "message": "Network error calling Microsoft Graph",
                "error": str(e),
                "hint": "Check internet connectivity, firewall/proxy rules, or try again.",
                **diag,
            },
        )

    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"status": "ERROR", "message": "Unhandled error in diag endpoint", "error": str(e), **diag},
        )


# ------------------------
# URL #2: Show all members of a group (live from Graph)
# ------------------------
@app.get("/api/group/{group_id}/members")
async def group_members(group_id: str):
    try:
        members = g.list_group_members(group_id)
        simplified = [
            {
                "id": m.get("id"),
                "displayName": m.get("displayName"),
                "mail": m.get("mail"),
                "userPrincipalName": m.get("userPrincipalName"),
            }
            for m in members
        ]
        return JSONResponse(status_code=status.HTTP_200_OK, content={"count": len(simplified), "members": simplified})
    except httpx.HTTPStatusError as e:
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content={
                "status": "ERROR",
                "message": "Graph error listing members",
                "error": {"status_code": e.response.status_code, "url": str(e.request.url), "body": e.response.text[:1500]},
                "hint": "Ensure Group.Read.All (and often Directory.Read.All) Application permissions with admin consent.",
            },
        )
    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"status": "ERROR", "message": "Unhandled error listing members", "error": str(e)},
        )


# ------------------------
# Graph handshake (GET) — records GET validations
# ------------------------
@app.get("/notifications")
async def validate(request: Request, validationToken: str | None = None):
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


# ------------------------
# Graph change notifications (POST) — handles POST validation too
# ------------------------
@app.post("/notifications")
async def notifications(request: Request):
    global LAST_POST, LAST_VALIDATION

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

    try:
        body = await request.json()
    except Exception:
        LAST_POST = {"when": _now_iso(), "error": "invalid_json"}
        # intentionally do not log invalid JSON repeatedly
        return JSONResponse({"error": "invalid_json"}, status_code=400)

    value = body.get("value") or []
    if not isinstance(value, list):
        LAST_POST = {"when": _now_iso(), "error": "bad_payload", "raw": body}
        # don't log bad payloads repeatedly
        return JSONResponse({"error": "bad_payload"}, status_code=400)

    # Verify clientState (if supplied)
    for n in value:
        incoming = (n.get("clientState") or "").strip()
        if CLIENT_STATE and incoming and incoming != CLIENT_STATE:
            LAST_POST = {"when": _now_iso(), "error": "client_state_mismatch", "raw": value}
            return JSONResponse({"error": "client_state_mismatch"}, status_code=403)

    # Extract group ids and user ids from resource
    changed_groups: list[str] = []
    changed_users: list[str] = []
    for n in value:
        res = (n.get("resource") or "").strip()

        m_group = re.match(r"^/?[Gg]roups/([0-9a-fA-F-]{36})(?:$|/)", res)
        if m_group:
            changed_groups.append(m_group.group(1))

        # /users/{userId}
        m_user = re.match(r"^/?[Uu]sers/([0-9a-fA-F-]{36})(?:$|/)", res)
        if m_user:
            changed_users.append(m_user.group(1))
            continue

        # /groups/{groupId}/members/{userId}
        m_member = re.match(r"^/?[Gg]roups/([0-9a-fA-F-]{36})/(?:members|owners)/([0-9a-fA-F-]{36})(?:$|/)?", res)
        if m_member:
            changed_users.append(m_member.group(2))

    # Deduplicate lists
    changed_groups = sorted(set(changed_groups))
    changed_users = sorted(set(changed_users))

    # If nothing interesting changed, ACK but don't log
    if not value or (not changed_groups and not changed_users):
        return JSONResponse(status_code=200, content=_ok("no-op notification"))

    # Dedup by a stable key derived from the interesting bits
    dedup_key = _hash_obj({"groups": changed_groups, "users": changed_users})
    if _seen_recent(dedup_key):
        # Already logged this combo recently; ACK but don't log again
        return JSONResponse(status_code=200, content=_ok("duplicate notification (suppressed)"))

    # -------------------
    # Expand user details + delta fallback
    # -------------------
    def _fmt_user(u: Dict[str, Any]) -> str:
        name = u.get("displayName") or u.get("userPrincipalName") or u.get("id")
        mail = u.get("mail") or "-"
        return f"{name} <{mail}>"

    expanded_users: List[Dict[str, Any]] = []
    expanded_added: List[Dict[str, Any]] = []
    expanded_removed: List[Dict[str, Any]] = []

    if changed_users:
        # Fast path: notification resource included /members/{userId}
        try:
            for uid in changed_users[:10]:  # keep webhook fast
                u = await _get_user_basic(uid)
                if u:
                    expanded_users.append(u)
        except Exception as e:
            logger.warning(f"[user-lookup fast-path] failed: {e}")
    else:
        # Fallback: Graph didn't include memberId => run one delta to figure out who changed
        try:
            target_group_id = (changed_groups[0] if changed_groups else None)
            if target_group_id:
                delta = await _members_delta_once(target_group_id)
                # Expand a few for readability
                for uid in delta["added"][:10]:
                    u = await _get_user_basic(uid)
                    if u: expanded_added.append(u)
                for uid in delta["removed"][:10]:
                    try:
                        u = await _get_user_basic(uid)
                    except Exception:
                        u = None
                    expanded_removed.append(u or {"id": uid, "displayName": None, "mail": None, "userPrincipalName": None})
        except Exception as e:
            logger.warning(f"[delta fallback] failed: {e}")

    # Build a friendly summary
    summary_parts = [f"{len(value)} notification(s)"]
    if changed_groups:
        summary_parts.append(f"groups: {', '.join(changed_groups)}")

    if expanded_users:
        summary_parts.append("users: " + "; ".join(_fmt_user(u) for u in expanded_users))
    else:
        if expanded_added:
            summary_parts.append("added: " + "; ".join(_fmt_user(u) for u in expanded_added))
        if expanded_removed:
            summary_parts.append("removed: " + "; ".join(_fmt_user(u) for u in expanded_removed))

    # -------------------

    info = {
        "when": _now_iso(),
        "client_ip": request.client.host if request.client else None,
        "count": len(value),
        "groups": changed_groups,
        "users": changed_users,
        "expanded_users": expanded_users,
        "expanded_added": expanded_added,
        "expanded_removed": expanded_removed,
        "raw": value,
        "summary": " | ".join(summary_parts),
    }
    LAST_POST = info
    logger.info(f"[notification] {info}")
    _append_event("notification", info)

    return JSONResponse(status_code=200, content=_ok("notification received", **info))


# ------------------------
# Debug + HTML log
# ------------------------
@app.get("/notifications/debug")
async def notifications_debug():
    _load_events_from_disk()
    return {"last_validation": LAST_VALIDATION, "last_post": LAST_POST, "events": EVENTS[-50:]}


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
