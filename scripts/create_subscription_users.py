# scripts/create_subscription_users.py
import os, sys, json, datetime, requests, urllib.parse
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

TENANT_ID     = os.environ["TENANT_ID"]
CLIENT_ID     = os.environ["CLIENT_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]

RAW_URL       = (os.environ["NOTIFICATION_URL"] or "").strip()
CLIENT_STATE  = os.getenv("CLIENT_STATE", "").strip()
GROUP_ID      = os.getenv("GROUP_ID", "").strip()  # REQUIRED: 70152fd3-14b9-4363-aa50-2ae1f30462d4
LATEST_TLS    = os.getenv("LATEST_TLS", "v1_2").strip()
SUB_MINUTES   = int(os.getenv("SUB_MINUTES", "4230"))  # max for directory resources
LIFECYCLE_URL = os.getenv("LIFECYCLE_URL", "").strip()

# Do NOT use includeResourceData for group membership; Graph won't give you email there.
WITH_RESOURCE_DATA  = False
ENCRYPTION_CERT_B64 = ""
ENCRYPTION_CERT_ID  = ""

AUTH_URL   = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"

def mask(v: str) -> str:
    return f"{v[:4]}…{v[-4:]}" if v and len(v) > 8 else v or "(empty)"

def normalize_url(url: str) -> str:
    u = urllib.parse.urlsplit(url.strip())
    if u.scheme.lower() != "https":
        raise ValueError("NOTIFICATION_URL must be HTTPS")
    path = (u.path or "").rstrip("/")
    if not path.endswith("/notifications"):
        path = (path + "/notifications").replace("//", "/")
    return urllib.parse.urlunsplit((u.scheme, u.netloc, path, u.query, u.fragment))

NOTIFICATION_URL = normalize_url(RAW_URL)

def get_token() -> str:
    r = requests.post(
        AUTH_URL,
        data={
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type": "client_credentials",
            "scope": "https://graph.microsoft.com/.default",
        },
        timeout=30,
    )
    r.raise_for_status()
    return r.json()["access_token"]

def preflight_notification_url():
    try:
        resp = requests.get(f"{NOTIFICATION_URL}?validationToken=ping", timeout=10)
        ok = (resp.status_code == 200 and resp.headers.get("content-type","").lower().startswith("text/plain"))
        return ok, resp.status_code, (resp.text[:200] if resp.text is not None else "")
    except Exception as e:
        return False, None, str(e)

def expiry_iso(minutes: int) -> str:
    return (datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=minutes)).replace(microsecond=0).isoformat().replace("+00:00","Z")

def base_payload() -> dict:
    if not GROUP_ID:
        raise ValueError("GROUP_ID is required.")
    payload = {
        "notificationUrl": NOTIFICATION_URL,
        "expirationDateTime": expiry_iso(SUB_MINUTES),
        "clientState": CLIENT_STATE,
        "latestSupportedTlsVersion": LATEST_TLS,
    }
    if LIFECYCLE_URL:
        payload["lifecycleNotificationUrl"] = LIFECYCLE_URL
    # includeResourceData is intentionally omitted for group membership
    return payload

# Exactly TWO subscriptions we want for this one group:
# 1) /groups/{gid}/members with created,deleted  → membership add/remove signals
# 2) /groups/{gid} with updated                  → backstop; your webhook calls members/delta to learn who changed
DESIRED = [
    {"resource": lambda gid: f"/groups/{gid}/members", "changeType": "created,deleted"},
    {"resource": lambda gid: f"/groups/{gid}",        "changeType": "updated"},
]

def create_subscription(resource: str, change_type: str, token: str):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = base_payload() | {"resource": resource, "changeType": change_type}
    print("[diag] Creating subscription with payload:")
    print(json.dumps(payload, indent=2))
    r = requests.post(f"{GRAPH_BASE}/subscriptions", headers=headers, json=payload, timeout=30)
    if r.status_code >= 400:
        print("[error]", r.status_code, r.text)
        if r.status_code == 400 and "ValidationError" in r.text:
            print("[hint] Webhook must echo ?validationToken=<token> as 200 text/plain within 10s (no auth).")
        r.raise_for_status()
    sub = r.json()
    print("[ok] Created subscription:")
    print(json.dumps(sub, indent=2))
    return sub

def list_subscriptions(token=None):
    token = token or get_token()
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(f"{GRAPH_BASE}/subscriptions", headers=headers, timeout=30)
    r.raise_for_status()
    return r.json().get("value", [])

def renew_subscription(sub_id: str):
    token = get_token()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    body = {"expirationDateTime": expiry_iso(SUB_MINUTES)}
    r = requests.patch(f"{GRAPH_BASE}/subscriptions/{sub_id}", headers=headers, json=body, timeout=30)
    if r.status_code >= 400:
        print("[renew error]", r.status_code, r.text)
        r.raise_for_status()
    print(f"[ok] Renewed subscription {sub_id} until {body['expirationDateTime']}")
    try:
        return r.json()
    except Exception:
        return {"id": sub_id, **body}

def ensure_only_for_group():
    ok, code, body = preflight_notification_url()
    print(f"[preflight] {NOTIFICATION_URL} ok={ok} status={code} body={body!r}")
    if not ok:
        print("[preflight] WARNING: webhook did not echo 200 text/plain; Graph validation may fail", file=sys.stderr)

    token = get_token()
    existing = list_subscriptions(token)

    # Remove any unrelated subs that point to our webhook (e.g., /users)
    headers = {"Authorization": f"Bearer {token}"}
    for s in existing:
        if s.get("notificationUrl") != NOTIFICATION_URL:
            continue
        res = s.get("resource", "")
        if res not in {f"/groups/{GROUP_ID}", f"/groups/{GROUP_ID}/members"}:
            sid = s.get("id")
            if sid:
                print(f"[cleanup] Deleting unrelated subscription {sid} resource={res}")
                requests.delete(f"{GRAPH_BASE}/subscriptions/{sid}", headers=headers, timeout=30)

    # Re-list after cleanup
    existing = list_subscriptions(token)

    # Ensure/renew the two desired subs
    results = []
    for spec in DESIRED:
        res = spec["resource"](GROUP_ID)
        ct  = spec["changeType"]
        match = next((s for s in existing
                      if s.get("notificationUrl")==NOTIFICATION_URL
                      and s.get("resource")==res
                      and s.get("changeType")==ct
                      and not s.get("includeResourceData")), None)
        if match:
            exp = match.get("expirationDateTime")
            print(f"[diag] Found existing sub {match['id']} for {res} exp={exp}")
            try:
                expires_at = datetime.datetime.fromisoformat((exp or "").replace("Z","+00:00"))
                delta = expires_at - datetime.datetime.now(datetime.UTC)
                if delta.total_seconds() < 5*24*3600:
                    results.append(renew_subscription(match["id"]))
                else:
                    print("[ok] Subscription still valid; no action")
                    results.append(match)
            except Exception:
                results.append(renew_subscription(match["id"]))
        else:
            results.append(create_subscription(res, ct, token))
    return results

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "ensure"
    print("[diag] TENANT:", mask(TENANT_ID), "CLIENT:", mask(CLIENT_ID))
    print("[diag] NOTIFICATION_URL:", NOTIFICATION_URL)
    print("[diag] GROUP_ID:", GROUP_ID or "(missing)")
    print("[diag] TLS:", LATEST_TLS or "(default)")
    if cmd == "list":
        print(json.dumps({"value": list_subscriptions()}, indent=2))
    elif cmd == "ensure":
        ensure_only_for_group()
    elif cmd == "renew":
        subs = list_subscriptions()
        for s in subs:
            if s.get("notificationUrl")==NOTIFICATION_URL and s.get("resource") in {f"/groups/{GROUP_ID}", f"/groups/{GROUP_ID}/members"}:
                renew_subscription(s["id"])
    else:
        ensure_only_for_group()
