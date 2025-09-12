# # main.py
# import os, hmac, json
# from collections import deque
# from datetime import datetime

# from fastapi import FastAPI, Request, Response
# from fastapi.responses import PlainTextResponse, JSONResponse, HTMLResponse
# from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
# from starlette.middleware.trustedhost import TrustedHostMiddleware

# app = FastAPI()

# # --- Middlewares ---
# app.add_middleware(HTTPSRedirectMiddleware)
# app.add_middleware(
#     TrustedHostMiddleware,
#     allowed_hosts=[
#         "*.azurewebsites.net",
#         "localhost",
#         "127.0.0.1",
#         "ad-aapi-test.eastus.cloudapp.azure.com",
#     ],
# )

# # --- Shared secret from env (for clientState check) ---
# CLIENT_STATE = (os.getenv("CLIENT_STATE") or "").strip()
# if not CLIENT_STATE:
#     raise RuntimeError("CLIENT_STATE environment variable is not set")

# # --- Keep last 50 notifications in memory ---
# RECENT_NOTIFICATIONS = deque(maxlen=50)

# @app.get("/")
# async def root():
#     return {"status": "OK", "message": "Azure AD Webhook POC is running"}

# @app.get("/healthz")
# async def healthz():
#     return {"ok": True}

# # 1) Validation handshake (Graph sends GET with ?validationToken=…)
# @app.get("/notifications")
# async def validate(validationToken: str | None = None):
#     if validationToken:
#         # Must echo token with 200 for Graph to accept the subscription
#         return PlainTextResponse(content=validationToken, status_code=200)
#     return JSONResponse({"status": "OK"}, status_code=200)

# # 2) Receive notifications (Graph sends POST)
# @app.post("/notifications")
# async def notifications(request: Request):
#     try:
#         body = await request.json()
#     except Exception:
#         return JSONResponse({"error": "invalid_json"}, status_code=400)

#     # Verify clientState for each notification (when present)
#     value = body.get("value")
#     if isinstance(value, list) and value:
#         for n in value:
#             incoming = (n.get("clientState") or "").strip()
#             if incoming and not hmac.compare_digest(incoming, CLIENT_STATE):
#                 return Response(status_code=401)

#     # Save the payload with a timestamp for later viewing
#     RECENT_NOTIFICATIONS.append({
#         "ts": datetime.utcnow().isoformat() + "Z",
#         "body": body,
#     })

#     # Log payload (flush so it appears immediately in App Service logs)
#     print("🔔 Incoming payload:", flush=True)
#     print(json.dumps(body, indent=2), flush=True)

#     # Always return 200 OK
#     return JSONResponse(content={"status": "ok"}, status_code=200)

# # 3) Browser endpoint to view last 50 payloads
# @app.get("/notifications/recent")
# async def recent_notifications(request: Request):
#     items = list(RECENT_NOTIFICATIONS)
#     # If browser asks for HTML, show a nice "waiting" message when empty
#     accept = request.headers.get("accept", "")
#     if "text/html" in accept:
#         if not items:
#             html = """
#             <!doctype html>
#             <html>
#               <head>
#                 <meta charset="utf-8"/>
#                 <title>Recent Notifications</title>
#                 <style>
#                   body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; padding: 2rem; }
#                   .muted { color: #666; }
#                   pre { background:#f6f8fa; padding:1rem; border-radius:8px; overflow:auto; }
#                 </style>
#               </head>
#               <body>
#                 <h1>Recent Notifications</h1>
#                 <p class="muted">No notifications yet — waiting for Microsoft Graph…</p>
#                 <p class="muted">Once a change occurs (created/updated/deleted), it will appear here.</p>
#               </body>
#             </html>
#             """
#             return HTMLResponse(html, status_code=200)
#         # If we do have items, render simple HTML
#         rows = "\n".join(
#             f"<h3>{i+1}. {n['ts']}</h3><pre>{json.dumps(n['body'], indent=2)}</pre>"
#             for i, n in enumerate(reversed(items))
#         )
#         html = f"""
#         <!doctype html>
#         <html>
#           <head>
#             <meta charset="utf-8"/>
#             <title>Recent Notifications</title>
#             <style>
#               body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; padding: 2rem; }}
#               .actions a {{ margin-right: 1rem; }}
#               pre {{ background:#f6f8fa; padding:1rem; border-radius:8px; overflow:auto; }}
#             </style>
#           </head>
#           <body>
#             <h1>Recent Notifications</h1>
#             <div class="actions">
#               <a href="/notifications/clear">Clear</a>
#               <a href="/notifications/recent">Refresh</a>
#             </div>
#             {rows}
#           </body>
#         </html>
#         """
#         return HTMLResponse(html, status_code=200)

#     # Default to JSON
#     if not items:
#         return JSONResponse(
#             {"status": "waiting", "message": "No notifications yet. Waiting for Microsoft Graph…"},
#             status_code=200,
#         )
#     return JSONResponse(items, status_code=200)

# # 4) Quick utility to clear the buffer from the browser
# @app.get("/notifications/clear")
# async def clear_notifications():
#     RECENT_NOTIFICATIONS.clear()
#     return JSONResponse({"cleared": True, "remaining": 0}, status_code=200)
import os, hmac, json
from fastapi import FastAPI, Request, Response
from fastapi.responses import PlainTextResponse, JSONResponse
 
app = FastAPI()
 
CLIENT_STATE = (os.getenv("CLIENT_STATE") or "").strip()
if not CLIENT_STATE:
    raise RuntimeError("CLIENT_STATE environment variable is not set")
 
@app.get("/")
async def root():
    return {"status": "OK", "message": "Azure AD Webhook POC is running"}
 
# Handle validation (GET or POST) and actual notifications
@app.api_route("/notifications", methods=["GET", "POST"])
async def notifications(request: Request, validationToken: str | None = None):
    # Validation handshake: Graph may call GET or POST with ?validationToken=...
    if validationToken:
        # Respond with plain text token and 200 OK
        return PlainTextResponse(validationToken, status_code=200)
 
    # Otherwise handle real notifications (POST with JSON)
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