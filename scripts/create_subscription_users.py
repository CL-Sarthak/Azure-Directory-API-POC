# scripts/create_subscription_users.py
import os, sys, json, datetime, requests, urllib.parse
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

TENANT_ID     = os.environ["TENANT_ID"]
CLIENT_ID     = os.environ["CLIENT_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]

RAW_URL       = (os.environ["NOTIFICATION_URL"] or "").strip()
CLIENT_STATE  = os.getenv("CLIENT_STATE", "").strip()
GROUP_ID      = os.getenv("GROUP_ID", "").strip()            # optional
LIFECYCLE_URL = os.getenv("LIFECYCLE_URL", "").strip()       # optional
LATEST_TLS    = os.getenv("LATEST_TLS", "v1_2").strip()      # optional: v1_0|v1_1|v1_2|v1_3
CHANGE_TYPES  = os.getenv("CHANGE_TYPES", "updated,deleted") # groups support updated (+created/soft delete) and deleted
# Default to 28 days for directory resources (max ~29 days per MS Graph)
SUB_MINUTES   = int(os.getenv("SUB_MINUTES", str(28 * 24 * 60)))

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
    """
    Basic reachability sanity check.
    NOTE: Graph will POST ?validationToken=...; this only verifies your endpoint answers something at all.
    """
    try:
        resp = requests.get(f"{NOTIFICATION_URL}?validationToken=ping", timeout=10)
        ok = (resp.status_code == 200 and resp.headers.get("content-type","").startswith("text/plain"))
        return ok, resp.status_code, resp.text[:200]
    except Exception as e:
        return False, None, str(e)

def resource_path() -> str:
    return f"/groups/{GROUP_ID}" if GROUP_ID else "/groups"

def expiry_iso(minutes: int) -> str:
    return (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=minutes)).replace(microsecond=0).isoformat()

def create_subscription():
    token = get_token()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    payload = {
        "changeType": CHANGE_TYPES,
        "notificationUrl": NOTIFICATION_URL,
        "resource": resource_path(),
        "expirationDateTime": expiry_iso(SUB_MINUTES),
        "clientState": CLIENT_STATE,
        # Nice-to-have hints to Graph:
        "latestSupportedTlsVersion": LATEST_TLS,
    }
    if LIFECYCLE_URL:
        payload["lifecycleNotificationUrl"] = LIFECYCLE_URL

    print("[diag] Creating subscription with payload:")
    print(json.dumps(payload, indent=2))

    r = requests.post(f"{GRAPH_BASE}/subscriptions", headers=headers, json=payload, timeout=30)
    if r.status_code >= 400:
        print("[error]", r.status_code, r.text)
        # Helpful hint for the very common validation failure:
        if r.status_code == 400 and "ValidationError" in r.text:
            print(
                "[hint] Graph validates by POSTing ?validationToken=... to your notificationUrl "
                "and requires a 200 text/plain echo within 10 seconds. "
                "Ensure your /notifications handler returns the raw token on POST as well as GET."
            )
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

def ensure_subscription():
    ok, code, body = preflight_notification_url()
    print(f"[preflight] {NOTIFICATION_URL} ok={ok} status={code} body={body!r}")
    if not ok:
        print("[preflight] WARNING: webhook did not echo 200 text/plain; Graph validation may fail", file=sys.stderr)

    token = get_token()
    subs = list_subscriptions(token)
    res  = resource_path()

    # Match on resource + URL + changeTypes
    match = next((s for s in subs
                  if s.get("resource") == res
                  and s.get("notificationUrl") == NOTIFICATION_URL
                  and s.get("changeType") == CHANGE_TYPES), None)

    if match:
        exp = match.get("expirationDateTime")
        print(f"[diag] Found existing sub {match['id']} exp={exp}")
        try:
            expires_at = datetime.datetime.fromisoformat((exp or "").replace("Z", "+00:00"))
            delta = expires_at - datetime.datetime.now(datetime.timezone.utc)
            # renew if < 5 days left
            if delta.total_seconds() < 5 * 24 * 3600:
                return renew_subscription(match["id"])
            print("[ok] Subscription still valid; no action")
            return match
        except Exception:
            return renew_subscription(match["id"])
    else:
        return create_subscription()

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "create"
    print("[diag] TENANT:", mask(TENANT_ID), "CLIENT:", mask(CLIENT_ID))
    print("[diag] NOTIFICATION_URL:", NOTIFICATION_URL)
    print("[diag] GROUP_ID:", GROUP_ID or "(all groups)")
    print("[diag] CHANGE_TYPES:", CHANGE_TYPES, "EXPIRES_IN_MIN:", SUB_MINUTES, "TLS:", LATEST_TLS or "(default)")

    if cmd == "list":
        print(json.dumps({"value": list_subscriptions()}, indent=2))
    elif cmd == "ensure":
        ensure_subscription()
    elif cmd == "renew":
        # renew first matching sub
        subs = list_subscriptions()
        res  = resource_path()
        match = next((s for s in subs
                      if s.get("resource")==res and s.get("notificationUrl")==NOTIFICATION_URL
                      and s.get("changeType")==CHANGE_TYPES), None)
        if not match:
            print("[renew] No matching subscription; creating new…")
            create_subscription()
        else:
            renew_subscription(match["id"])
    else:
        create_subscription()
