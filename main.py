import os, hmac, json
from fastapi import FastAPI, Request, Response
from fastapi.responses import PlainTextResponse, JSONResponse
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

app = FastAPI()

app.add_middleware(HTTPSRedirectMiddleware)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*.azurewebsites.net", "localhost", "127.0.0.1"]
)
# Load shared secret from env
CLIENT_STATE = (os.getenv("CLIENT_STATE") or "").strip()
if not CLIENT_STATE:
    raise RuntimeError("CLIENT_STATE environment variable is not set")

@app.get("/")
async def root():
    return {"status": "OK", "message": "Azure AD Webhook POC is running"}

# 1) Validation handshake
@app.get("/notifications")
async def validate(validationToken: str | None = None):
    if validationToken:
        return PlainTextResponse(validationToken, status_code=200)
    return {"status": "OK"}

# 2) Receive notifications
@app.post("/notifications")
async def notifications(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid_json"}, status_code=400)

    # Verify clientState if present
    value = body.get("value")
    if isinstance(value, list) and value:
        for n in value:
            incoming = (n.get("clientState") or "").strip()
            if not hmac.compare_digest(incoming, CLIENT_STATE):
                return Response(status_code=401)

    print("🔔 Incoming payload:")
    print(json.dumps(body, indent=2))

    return JSONResponse(content=body, status_code=200)
