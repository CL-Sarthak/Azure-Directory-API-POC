# scripts/create_subscription_users.py
import os
import requests
import datetime
import sys

# --- Required env vars ---
try:
    TENANT_ID = os.environ["TENANT_ID"]
    CLIENT_ID = os.environ["CLIENT_ID"]
    CLIENT_SECRET = os.environ["CLIENT_SECRET"]
    NOTIFICATION_URL = os.environ["NOTIFICATION_URL"]  # e.g., https://<app>.azurewebsites.net/notifications
except KeyError as e:
    print(f"Missing env var: {e.args[0]}")
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

    # Use a long validity for POC so you don't need renewal.
    # (users resource allows long expirations; set safely under the max)
    expiration = (datetime.datetime.utcnow() + datetime.timedelta(days=27)).isoformat() + "Z"

    payload = {
        # All three = full user lifecycle coverage (see note below)
        "changeType": "created,updated,deleted",
        "notificationUrl": NOTIFICATION_URL,
        "resource": "users",
        "expirationDateTime": expiration,
        "clientState": CLIENT_STATE,
        # Tip: omit includeResourceData for simple POC payloads
    }

    resp = requests.post(
        "https://graph.microsoft.com/v1.0/subscriptions",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json=payload,
        timeout=30,
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
            print("\nRemember: keep your FastAPI /notifications endpoint publicly reachable (HTTPS)")
            print("and echo the validationToken on creation so Graph accepts the subscription.")
    except Exception:
        print("Raw response:", resp.text)

if __name__ == "__main__":
    main()
