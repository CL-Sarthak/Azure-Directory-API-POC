# scripts/create_subscription_users.py
import os, sys, json, datetime, requests
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

TENANT_ID = os.environ["TENANT_ID"]
CLIENT_ID = os.environ["CLIENT_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]
NOTIFICATION_URL = os.environ["NOTIFICATION_URL"]
CLIENT_STATE = os.getenv("CLIENT_STATE", "")
GROUP_ID = os.getenv("GROUP_ID", "").strip()  # optional

AUTH_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"

def mask(v): 
    return f"{v[:4]}…{v[-4:]}" if v and len(v) > 8 else v or "(empty)"

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

def create_subscription():
    token = get_token()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # Watch one group if GROUP_ID set; else watch all groups
    resource = f"/groups/{GROUP_ID}" if GROUP_ID else "/groups"
    # group membership changes are "updated" on the group resource
    changeType = "updated"

    # Expire in ~60 minutes (renew as needed)
    exp = (datetime.datetime.utcnow() + datetime.timedelta(minutes=60)).replace(microsecond=0).isoformat() + "Z"

    payload = {
        "changeType": changeType,
        "notificationUrl": NOTIFICATION_URL,
        "resource": resource,
        "expirationDateTime": exp,
        "clientState": CLIENT_STATE,
    }

    print("[diag] Creating subscription with payload:")
    print(json.dumps(payload, indent=2))

    r = requests.post(f"{GRAPH_BASE}/subscriptions", headers=headers, json=payload, timeout=30)
    if r.status_code >= 400:
        print("[error]", r.status_code, r.text)
        r.raise_for_status()
    sub = r.json()
    print("[ok] Created subscription:")
    print(json.dumps(sub, indent=2))
    return sub

def list_subscriptions():
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(f"{GRAPH_BASE}/subscriptions", headers=headers, timeout=30)
    r.raise_for_status()
    subs = r.json()
    print(json.dumps(subs, indent=2))
    return subs

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "create"
    print("[diag] TENANT:", mask(TENANT_ID), "CLIENT:", mask(CLIENT_ID))
    print("[diag] NOTIFICATION_URL:", NOTIFICATION_URL)
    print("[diag] GROUP_ID:", GROUP_ID or "(all groups)")

    if cmd == "list":
        list_subscriptions()
    else:
        create_subscription()
