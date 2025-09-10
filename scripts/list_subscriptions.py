import os, requests
TENANT_ID, CLIENT_ID, CLIENT_SECRET = os.environ["TENANT_ID"], os.environ["CLIENT_ID"], os.environ["CLIENT_SECRET"]
tok = requests.post(
    f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token",
    data={"grant_type":"client_credentials","client_id":CLIENT_ID,"client_secret":CLIENT_SECRET,"scope":"https://graph.microsoft.com/.default"},
    timeout=30
).json()["access_token"]

r = requests.get("https://graph.microsoft.com/v1.0/subscriptions",
                 headers={"Authorization": f"Bearer {tok}"}, timeout=30)
print(r.status_code)
print(r.json())
