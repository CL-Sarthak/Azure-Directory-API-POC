import os
from fastapi import FastAPI, Request
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = FastAPI()

@app.get("/")
async def root():
    return {"status": "OK", "message": "Azure AD Webhook POC is running"}

@app.post("/notifications")
async def notifications(request: Request):
    body = await request.json()

    # Handle validation token (when MS Graph sets up subscription)
    if "validationToken" in body:
        return body["validationToken"]

    # For POC: just print the payload
    print("Received notification payload:", body)

    return {"status": "received"}
