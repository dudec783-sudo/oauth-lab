from flask import Flask, redirect, request, session
import requests
import os
import base64
import hashlib
import secrets
import json
import urllib.parse

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")

TENANT_ID = os.environ.get("AZURE_TENANT_ID", "common")
CLIENT_ID = os.environ.get("AZURE_CLIENT_ID")
REDIRECT_URI = os.environ.get("REDIRECT_URI")

# Validate required environment variables
if not CLIENT_ID or not REDIRECT_URI:
    raise ValueError("Missing required environment variables: AZURE_CLIENT_ID and REDIRECT_URI")

# -----------------------
# Helper: Decode JWT
# -----------------------
def decode_jwt(token):
    try:
        parts = token.split(".")
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}

# -----------------------
# HOME UI
# -----------------------
@app.route("/")
def home():
    data = session.get("flow_data")

    return f"""
    <h1>OAuth Lab</h1>

    <h3>Easy Auth</h3>
    <a href="/login">Login with Microsoft</a>

    <h3>Custom Flows</h3>
    <a href="/pkce/start">Start PKCE Flow</a>

    <hr>

    <h2>Flow Output</h2>
    <pre>{json.dumps(data, indent=2)}</pre>
    """

# -----------------------
# EASY AUTH LOGIN
# -----------------------
@app.route("/login")
def login():
    return redirect("/.auth/login/aad")

# -----------------------
# PKCE START
# -----------------------
@app.route("/pkce/start")
def pkce_start():
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode().rstrip("=")

    state = secrets.token_urlsafe(16)

    session["code_verifier"] = code_verifier
    session["state"] = state

    auth_url = (
        f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/authorize?"
        f"client_id={CLIENT_ID}"
        f"&response_type=code"
        f"&redirect_uri={urllib.parse.quote(REDIRECT_URI)}"
        f"&scope=openid profile email offline_access"
        f"&state={state}"
        f"&code_challenge={code_challenge}"
        f"&code_challenge_method=S256"
    )

    return redirect(auth_url)

# -----------------------
# CALLBACK
# -----------------------
@app.route("/callback")
def callback():
    code = request.args.get("code")
    state = request.args.get("state")
    
    # Validate state parameter
    if state != session.get("state"):
        return "Invalid state parameter", 400

    token_url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"

    data = {
        "client_id": CLIENT_ID,
        "client_secret": os.environ.get("AZURE_CLIENT_SECRET"), 
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": session.get("code_verifier"),
    }

    res = requests.post(token_url, data=data)
    if not res.ok:
        return f"Token request failed: {res.text}", 400
    
    token_json = res.json()

    id_token = token_json.get("id_token", "")
    access_token = token_json.get("access_token", "")

    session["flow_data"] = {
        "flow": "PKCE",
        "token_response": token_json,
        "decoded_id_token": decode_jwt(id_token),
        "decoded_access_token": decode_jwt(access_token)
    }

    return redirect("/")

# -----------------------
# RUN
# -----------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)