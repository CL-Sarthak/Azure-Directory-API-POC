# app/graph.py
import os
import time
import httpx

TENANT_ID = os.getenv("TENANT_ID", "").strip()
CLIENT_ID = os.getenv("CLIENT_ID", "").strip()
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "").strip()

AUTH_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"

# Tiny in-process token cache
_token_cache = {"access_token": None, "expires_at": 0}

def _mask(v: str) -> str:
    return f"{v[:4]}…{v[-4:]}" if v and len(v) > 8 else v or "(empty)"

def _now() -> int:
    return int(time.time())

def get_token() -> str:
    """Client-credentials token for Microsoft Graph."""
    global _token_cache
    if _token_cache["access_token"] and _token_cache["expires_at"] - 60 > _now():
        return _token_cache["access_token"]

    if not (TENANT_ID and CLIENT_ID and CLIENT_SECRET):
        raise RuntimeError("Missing TENANT_ID / CLIENT_ID / CLIENT_SECRET")

    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "client_credentials",
        "scope": "https://graph.microsoft.com/.default",
    }
    with httpx.Client(timeout=20) as c:
        resp = c.post(AUTH_URL, data=data)
        resp.raise_for_status()
        payload = resp.json()
    access_token = payload["access_token"]
    # Default to 1 hour if not provided
    expires_in = int(payload.get("expires_in", 3600))
    _token_cache = {
        "access_token": access_token,
        "expires_at": _now() + expires_in,
    }
    return access_token

def graph_get(path: str, params: dict | None = None) -> dict:
    """Simple GET wrapper."""
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{GRAPH_BASE}{path}"
    with httpx.Client(timeout=30) as c:
        r = c.get(url, headers=headers, params=params)
        r.raise_for_status()
        return r.json()

def list_group_members(group_id: str) -> list[dict]:
    """Return ALL members of a group (handles paging)."""
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{GRAPH_BASE}/groups/{group_id}/members"
    items: list[dict] = []

    with httpx.Client(timeout=30) as c:
        while True:
            r = c.get(url, headers=headers, params={"$select": "id,displayName,mail,userPrincipalName"})
            r.raise_for_status()
            data = r.json()
            items.extend(data.get("value", []))
            next_link = data.get("@odata.nextLink")
            if not next_link:
                break
            url = next_link  # already absolute
    return items

def diag_first_user() -> dict:
    """Read one user to prove Graph access works."""
    data = graph_get("/users", params={"$top": 1, "$select": "id,displayName,mail,userPrincipalName"})
    value = data.get("value", [])
    return value[0] if value else {}

