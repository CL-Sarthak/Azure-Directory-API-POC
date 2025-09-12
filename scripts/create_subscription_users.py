# scripts/create_subscription_users.py
import os, sys, requests, datetime
from dotenv import load_dotenv, find_dotenv

# Load .env from project root (or wherever it is)
load_dotenv(find_dotenv())

def _diag():
    # Tiny diagnostic to show what the process sees (masked)
    def mask(v): 
        return f"{v[:4]}…{v[-4:]}" if v and len(v) > 8 else v or "(empty)"
    print("[diag] CWD:", os.getcwd())
    print("[diag] TENANT_ID:", mask(os.getenv("TENANT_ID")))
    print("[diag] CLIENT_ID:", mask(os.getenv("CLIENT_ID")))
    print("[diag] CLIENT_SECRET set?:", "yes" if os.getenv("CLIENT_SECRET") else "no")
    print("[diag] NOTIFICATION_URL:", os.getenv("NOTIFICATION_URL"))
    print("[diag] CLIENT_STATE:", os.getenv("CLIENT_STATE") or "(default)")

_diag()

# --- Required env vars ---
try:
    TENANT_ID = os.environ["TENANT_ID"]
    CLIENT_ID = os.environ["CLIENT_ID"]
    CLIENT_SECRET = os.environ["CLIENT_SECRET"]
    NOTIFICATION_URL = os.environ["NOTIFICATION_URL"]
except KeyError as e:
    print(f"Missing env var: {e.args[0]}")
    print("Tip: ensure a .env file exists and the script is reading it, or export vars in your shell.")
    sys.exit(1)

CLIENT_STATE = os.getenv("CLIENT_STATE", "poc-secret-value")

def get_app_token() -> str:
    resp = requests.post(
        f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token",
        data={
            "grant_type": "client_credentials",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "scope": "https://graph.microsoft.com/.default",
        },
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]

def main():
    token = get_app_token()
    expiration = (datetime.datetime.utcnow() + datetime.timedelta(days=27)).isoformat() + "Z"
    payload = {
        "changeType": "created,updated,deleted",
        "notificationUrl": NOTIFICATION_URL,
        "resource": "users",
        "expirationDateTime": expiration,
        "clientState": CLIENT_STATE,
    }
    resp = requests.post(
        "https://graph.microsoft.com/v1.0/subscriptions",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json=payload, timeout=30,
    )
    print("Status:", resp.status_code)
    try:
        data = resp.json()
        print("Response:", data)
        if resp.ok:
            print("\n✅ Subscription created.")
            print("   id:", data.get("id"))
            print("   resource:", data.get("resource"))
            print("   expires:", data.get("expirationDateTime"))
            print("\nMake sure your /notifications endpoint is HTTPS and echoes validationToken.")
    except Exception:
        print("Raw response:", resp.text)

if __name__ == "__main__":
    main()
