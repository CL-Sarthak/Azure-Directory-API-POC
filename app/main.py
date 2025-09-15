# app/main.py
import os
import re
import httpx
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse, PlainTextResponse
from dotenv import load_dotenv

# Load .env once at startup
load_dotenv()

# local imports after dotenv so env is available
from app import graph as g  # noqa: E402

app = FastAPI(title="Azure AD Webhook + Graph POC")

CLIENT_STATE = (os.getenv("CLIENT_STATE") or "").strip()
NOTIFICATION_URL = os.getenv("NOTIFICATION_URL") or ""

def _mask(v: str) -> str:
    return f"{v[:4]}…{v[-4:]}" if v and len(v) > 8 else v or "(empty)"

def _ok(msg: str, **extra):
    return {"status": "OK", "message": msg, **extra}

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
    """
    Quick connectivity check to Microsoft Graph using app-only creds.
    - Success: returns sample user + masked env state.
    - Failure: returns structured error with hints.
    Add `?raw=1` to include full Graph error body (can be long).
    """
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
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"count": len(simplified), "members": simplified},
        )
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
# Graph handshake (GET)
# ------------------------
@app.get("/notifications")
async def validate(validationToken: str | None = None):
    if validationToken:
        # Echo token back with 200 to validate the webhook URL
        return PlainTextResponse(validationToken, status_code=200)
    return JSONResponse(status_code=200, content=_ok("notifications GET (no token)"))

# ------------------------
# Graph change notifications (POST)
# ------------------------
@app.post("/notifications")
async def notifications(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid_json"}, status_code=400)

    value = body.get("value") or []
    if not isinstance(value, list):
        return JSONResponse({"error": "bad_payload"}, status_code=400)

    # Verify clientState (if supplied)
    for n in value:
        incoming = (n.get("clientState") or "").strip()
        if CLIENT_STATE and incoming and incoming != CLIENT_STATE:
            return JSONResponse({"error": "client_state_mismatch"}, status_code=403)

    # Extract changed group IDs from resource like "/groups/{id}"
    changed_groups: list[str] = []
    for n in value:
        res = (n.get("resource") or "").strip()
        m = re.match(r"^/groups/([0-9a-fA-F-]{36})(?:$|/)", res)
        if m:
            changed_groups.append(m.group(1))

    return JSONResponse(
        status_code=200,
        content=_ok("notification received", count=len(value), groups=changed_groups, raw=value),
    )
