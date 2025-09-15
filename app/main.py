# app/main.py
import os, json, re
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, JSONResponse
from dotenv import load_dotenv

load_dotenv()  # load .env at startup

from app.graph import diag_first_user, list_group_members  # noqa: E402

CLIENT_STATE = (os.getenv("CLIENT_STATE") or "").strip()

app = FastAPI(title="Azure AD Webhook + Graph POC")

def _ok(msg: str, **extra):
    return {"status": "OK", "message": msg, **extra}

def _mask(v: str) -> str:
    return f"{v[:4]}…{v[-4:]}" if v and len(v) > 8 else v or "(empty)"

# --- Basic health
@app.get("/")
async def root():
    return _ok("API running", notification_url=os.getenv("NOTIFICATION_URL"))

# --- URL #1: Graph connectivity diagnostic
@app.get("/api/graph/diag")
async def graph_diag():
    # Proves token + a simple Graph /users read works
    user = diag_first_user()
    return _ok(
        "Graph reachable",
        saw_user=bool(user),
        sample_user=user,
        tenant=_mask(os.getenv("TENANT_ID") or ""),
        client=_mask(os.getenv("CLIENT_ID") or "")
    )

# --- URL #2: Show all members of a group (live)
@app.get("/api/group/{group_id}/members")
async def group_members(group_id: str):
    members = list_group_members(group_id)
    # Make the output easy to eyeball
    simplified = [
        {
            "id": m.get("id"),
            "displayName": m.get("displayName"),
            "mail": m.get("mail"),
            "userPrincipalName": m.get("userPrincipalName"),
        }
        for m in members
    ]
    return {"count": len(simplified), "members": simplified}

# --- Graph handshake (GET) ---
@app.get("/notifications")
async def validate(validationToken: str | None = None):
    if validationToken:
        # IMPORTANT: Graph expects the raw token back as text with 200
        return PlainTextResponse(validationToken, status_code=200)
    return _ok("notifications GET (no token)")

# --- Graph change notifications (POST) ---
@app.post("/notifications")
async def notifications(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid_json"}, status_code=400)

    value = body.get("value") or []
    # Basic shape validation
    if not isinstance(value, list):
        return JSONResponse({"error": "bad_payload"}, status_code=400)

    # Verify clientState (if present)
    for n in value:
        incoming = (n.get("clientState") or "").strip()
        if CLIENT_STATE and incoming and incoming != CLIENT_STATE:
            return JSONResponse({"error": "client_state_mismatch"}, status_code=403)

    # Extract changed group IDs, e.g. "/groups/{id}"
    changed_groups: list[str] = []
    for n in value:
        res = (n.get("resource") or "").strip()
        m = re.match(r"^/groups/([0-9a-fA-F-]{36})(?:$|/)", res)
        if m:
            changed_groups.append(m.group(1))

    # For demo, just echo what we got. (You can kick off delta reads here.)
    return _ok("notification received", count=len(value), groups=changed_groups, raw=value)
