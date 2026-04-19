"""
OAuth 2.0 Learning Lab - Complete Multi-Flow Implementation
Demonstrates Authorization Code, PKCE, Client Credentials, and Device Code flows
"""

from flask import Flask, redirect, request, session, render_template_string
import requests
import os
import base64
import hashlib
import secrets
import json
import urllib.parse
import time

# =====================================================================
# FLASK APP INITIALIZATION
# =====================================================================
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-in-production")

# =====================================================================
# ENVIRONMENT CONFIGURATION
# =====================================================================
TENANT_ID = os.environ.get("AZURE_TENANT_ID", "common")
CLIENT_ID = os.environ.get("AZURE_CLIENT_ID")
CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET")
REDIRECT_URI = os.environ.get("REDIRECT_URI", "http://localhost:8000/callback")

# Validate required environment variables at startup
if not CLIENT_ID:
    raise ValueError("ERROR: AZURE_CLIENT_ID environment variable is required")
if not REDIRECT_URI:
    raise ValueError("ERROR: REDIRECT_URI environment variable is required")

# OAuth 2.0 Endpoints
AUTH_ENDPOINT = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/authorize"
TOKEN_ENDPOINT = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
DEVICECODE_ENDPOINT = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/devicecode"

# =====================================================================
# HELPER FUNCTIONS
# =====================================================================

def decode_jwt(token):
    """
    Decode JWT token without signature verification (for learning purposes).
    In production, always verify the signature!
    """
    if not token:
        return None
    try:
        # JWT format: header.payload.signature
        parts = token.split(".")
        if len(parts) != 3:
            return {"error": "Invalid token format"}
        
        # Add padding if needed
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception as e:
        return {"error": str(e)}


def generate_auth_url(flow_type="pkce", scope="openid profile email"):
    """
    Generate Azure AD authorization URL for OAuth flows
    """
    state = secrets.token_urlsafe(16)
    session[f"{flow_type}_state"] = state
    
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": scope,
        "state": state,
    }
    
    # Add PKCE parameters
    if flow_type == "pkce":
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode().rstrip("=")
        
        session[f"{flow_type}_code_verifier"] = code_verifier
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = "S256"
    
    # Build URL
    query_string = "&".join([f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items()])
    auth_url = f"{AUTH_ENDPOINT}?{query_string}"
    
    return auth_url


def format_json(data):
    """Pretty print JSON with syntax highlighting"""
    try:
        return json.dumps(data, indent=2)
    except:
        return str(data)


# =====================================================================
# HTML TEMPLATES
# =====================================================================

HOME_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>OAuth 2.0 Learning Lab</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
        h1 { color: #0078d4; border-bottom: 2px solid #0078d4; padding-bottom: 10px; }
        h2 { color: #333; margin-top: 30px; }
        .flow-section { background: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .button { display: inline-block; padding: 10px 20px; margin: 5px; background: #0078d4; color: white; text-decoration: none; border-radius: 3px; cursor: pointer; border: none; font-size: 14px; }
        .button:hover { background: #005a9e; }
        .button.secondary { background: #6c757d; }
        .button.secondary:hover { background: #545b62; }
        .output { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 3px; padding: 15px; margin-top: 10px; font-family: monospace; font-size: 12px; max-height: 400px; overflow: auto; }
        .token-section { margin: 15px 0; }
        .token-section h4 { background: #e9ecef; padding: 10px; margin: 0; border-radius: 3px 3px 0 0; }
        .error { background: #f8d7da; color: #721c24; padding: 12px; border-radius: 3px; margin: 10px 0; border: 1px solid #f5c6cb; }
        .success { background: #d4edda; color: #155724; padding: 12px; border-radius: 3px; margin: 10px 0; border: 1px solid #c3e6cb; }
        .info { background: #d1ecf1; color: #0c5460; padding: 12px; border-radius: 3px; margin: 10px 0; border: 1px solid #bee5eb; }
        pre { background: white; border: 1px solid #dee2e6; padding: 10px; border-radius: 3px; overflow-x: auto; }
        .metadata { background: #fff3cd; border: 1px solid #ffc107; padding: 10px; border-radius: 3px; margin: 10px 0; font-size: 12px; }
    </style>
</head>
<body>
    <h1>🔐 OAuth 2.0 Learning Lab</h1>
    <p>Explore and understand OAuth 2.0 flows with Azure AD (Microsoft Entra ID)</p>

    <!-- Configuration Status -->
    <div class="flow-section">
        <h2>Configuration Status</h2>
        <div class="info">
            <strong>Environment:</strong> AZURE_TENANT_ID={tenant}<br>
            <strong>Client ID:</strong> {client_id_display}<br>
            <strong>Redirect URI:</strong> {redirect_uri}
        </div>
    </div>

    <!-- Authorization Code Flow with PKCE -->
    <div class="flow-section">
        <h2>1. Authorization Code Flow (PKCE)</h2>
        <p><strong>Best for:</strong> Web apps. Most secure. Uses authorization code + PKCE for code exchange.</p>
        <button class="button" onclick="window.location='/pkce/start'">Start PKCE Flow</button>
        <div class="metadata">
            • Generates code_challenge (S256)<br>
            • User logs in and grants permission<br>
            • Server receives authorization code<br>
            • Server exchanges code for tokens using code_verifier
        </div>
    </div>

    <!-- Client Credentials Flow -->
    <div class="flow-section">
        <h2>2. Client Credentials Flow</h2>
        <p><strong>Best for:</strong> Server-to-server, no user interaction. Requires Client Secret.</p>
        <button class="button secondary" onclick="window.location='/clientcreds/start'">Start Client Credentials Flow</button>
        <div class="metadata">
            • App authenticates directly to Azure AD<br>
            • No user involved<br>
            • Server sends Client ID + Secret<br>
            • Returns access token only (no ID token)
        </div>
    </div>

    <!-- Device Code Flow -->
    <div class="flow-section">
        <h2>3. Device Code Flow</h2>
        <p><strong>Best for:</strong> Devices without browsers, CLI tools, IoT devices.</p>
        <button class="button secondary" onclick="window.location='/device/start'">Start Device Code Flow</button>
        <div class="metadata">
            • Device requests code from Azure AD<br>
            • User sees code and visits authentication URL on another device<br>
            • Device polls for completion<br>
            • Returns tokens once user completes authentication
        </div>
    </div>

    <!-- Display Flow Results -->
    {flow_output}

    <!-- Configuration Guide -->
    <div class="flow-section">
        <h2>Setup Instructions</h2>
        <h3>Required Environment Variables:</h3>
        <pre>
AZURE_TENANT_ID=your-tenant-id      (or "common" for multi-tenant)
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret
REDIRECT_URI=http://localhost:8000/callback
SECRET_KEY=your-secret-key
        </pre>
        <h3>Azure AD App Registration Steps:</h3>
        <ol>
            <li>Go to Azure Portal → Microsoft Entra ID → App registrations</li>
            <li>Click "New registration"</li>
            <li>Name: "OAuth Lab" → Register</li>
            <li>Copy Client ID (Application ID)</li>
            <li>Go to "Certificates & secrets" → New client secret → Copy value</li>
            <li>Go to "Authentication" → Add Redirect URI: http://localhost:8000/callback</li>
            <li>Go to "API permissions" → Add "Microsoft Graph" → "User.Read"</li>
            <li>Grant admin consent</li>
        </ol>
    </div>

    <hr>
    <p><small>OAuth 2.0 Learning Lab | For educational purposes | Always verify token signatures in production</small></p>
</body>
</html>
"""

FLOW_OUTPUT_TEMPLATE = """
<div class="flow-section">
    <h2>Flow Results</h2>
    
    {error_display}
    {success_display}
    
    <div class="token-section">
        <h4>Raw Token Response</h4>
        <div class="output"><pre>{token_response}</pre></div>
    </div>
    
    {id_token_display}
    {access_token_display}
    
    <div class="metadata">
        <strong>Flow Type:</strong> {flow_type}<br>
        <strong>Timestamp:</strong> {timestamp}<br>
        <strong>State:</strong> {state}
    </div>
    
    <button class="button" onclick="window.location='/'">Clear & Start New Flow</button>
</div>
"""

# =====================================================================
# ROUTES: HOME & MAIN PAGE
# =====================================================================

@app.route("/")
def home():
    """
    Main home page showing available OAuth flows and results
    """
    flow_data = session.get("flow_data")
    flow_output = ""
    
    if flow_data:
        # Build token displays
        id_token_html = ""
        access_token_html = ""
        error_html = ""
        success_html = ""
        
        # Check for errors
        if flow_data.get("error"):
            error_html = f'<div class="error"><strong>Error:</strong> {flow_data.get("error")}</div>'
        else:
            success_html = '<div class="success"><strong>✓ Success!</strong> Tokens received</div>'
        
        # ID Token
        if flow_data.get("decoded_id_token"):
            id_token_html = f"""
            <div class="token-section">
                <h4>Decoded ID Token (User Info)</h4>
                <div class="output"><pre>{format_json(flow_data.get("decoded_id_token"))}</pre></div>
            </div>
            """
        
        # Access Token
        if flow_data.get("decoded_access_token"):
            access_token_html = f"""
            <div class="token-section">
                <h4>Decoded Access Token (Permissions)</h4>
                <div class="output"><pre>{format_json(flow_data.get("decoded_access_token"))}</pre></div>
            </div>
            """
        
        flow_output = FLOW_OUTPUT_TEMPLATE.format(
            error_display=error_html,
            success_display=success_html,
            token_response=format_json(flow_data.get("token_response", {})),
            id_token_display=id_token_html,
            access_token_display=access_token_html,
            flow_type=flow_data.get("flow_type", "Unknown"),
            timestamp=flow_data.get("timestamp", ""),
            state=flow_data.get("state", "N/A")
        )
    
    client_id_display = CLIENT_ID[:10] + "***" if CLIENT_ID else "NOT SET"
    
    html = HOME_TEMPLATE.format(
        tenant=TENANT_ID,
        client_id_display=client_id_display,
        redirect_uri=REDIRECT_URI,
        flow_output=flow_output
    )
    
    return html


# =====================================================================
# ROUTES: PKCE FLOW (Authorization Code with PKCE)
# =====================================================================

@app.route("/pkce/start")
def pkce_start():
    """
    Start PKCE flow by redirecting to Azure AD
    """
    try:
        auth_url = generate_auth_url(flow_type="pkce", scope="openid profile email offline_access")
        return redirect(auth_url)
    except Exception as e:
        session["flow_data"] = {
            "error": f"Failed to start PKCE flow: {str(e)}",
            "flow_type": "PKCE"
        }
        return redirect("/")


# =====================================================================
# ROUTES: CLIENT CREDENTIALS FLOW
# =====================================================================

@app.route("/clientcreds/start")
def clientcreds_start():
    """
    Start Client Credentials flow (server-to-server authentication)
    """
    if not CLIENT_SECRET:
        session["flow_data"] = {
            "error": "Client Credentials flow requires AZURE_CLIENT_SECRET environment variable",
            "flow_type": "Client Credentials"
        }
        return redirect("/")
    
    try:
        # Request token directly without user interaction
        token_data = {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type": "client_credentials",
            "scope": "https://graph.microsoft.com/.default"
        }
        
        response = requests.post(TOKEN_ENDPOINT, data=token_data, timeout=10)
        
        if not response.ok:
            session["flow_data"] = {
                "error": f"Token request failed: {response.status_code} - {response.text}",
                "flow_type": "Client Credentials",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            return redirect("/")
        
        token_json = response.json()
        access_token = token_json.get("access_token", "")
        
        session["flow_data"] = {
            "flow_type": "Client Credentials",
            "token_response": token_json,
            "decoded_access_token": decode_jwt(access_token),
            "decoded_id_token": None,  # No ID token in client credentials flow
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "state": "N/A (no user interaction)"
        }
        
    except Exception as e:
        session["flow_data"] = {
            "error": f"Exception during Client Credentials flow: {str(e)}",
            "flow_type": "Client Credentials"
        }
    
    return redirect("/")


# =====================================================================
# ROUTES: DEVICE CODE FLOW
# =====================================================================

@app.route("/device/start")
def device_start():
    """
    Start Device Code flow (for devices without browsers)
    """
    try:
        # Step 1: Request device code
        device_data = {
            "client_id": CLIENT_ID,
            "scope": "openid profile email offline_access"
        }
        
        response = requests.post(DEVICECODE_ENDPOINT, data=device_data, timeout=10)
        
        if not response.ok:
            session["flow_data"] = {
                "error": f"Device code request failed: {response.status_code} - {response.text}",
                "flow_type": "Device Code",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            return redirect("/")
        
        device_json = response.json()
        device_code = device_json.get("device_code")
        user_code = device_json.get("user_code")
        verification_uri = device_json.get("verification_uri")
        expires_in = device_json.get("expires_in", 900)
        interval = device_json.get("interval", 5)
        
        # Store device code for polling
        session["device_code"] = device_code
        session["device_polling_start"] = time.time()
        session["device_polling_expires"] = expires_in
        session["device_polling_interval"] = interval
        
        # Store and show instructions
        session["flow_data"] = {
            "flow_type": "Device Code",
            "device_code_info": {
                "user_code": user_code,
                "verification_uri": verification_uri,
                "instruction": f"Visit {verification_uri} and enter code: {user_code}",
                "expires_in": expires_in
            },
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "state": "Waiting for user authentication..."
        }
        
        # Immediately start polling
        return redirect("/device/poll")
        
    except Exception as e:
        session["flow_data"] = {
            "error": f"Exception during Device Code flow: {str(e)}",
            "flow_type": "Device Code"
        }
    
    return redirect("/")


@app.route("/device/poll")
def device_poll():
    """
    Poll for device code flow completion
    """
    device_code = session.get("device_code")
    polling_start = session.get("device_polling_start", 0)
    polling_expires = session.get("device_polling_expires", 900)
    
    if not device_code:
        return redirect("/")
    
    # Check if polling has expired
    if time.time() - polling_start > polling_expires:
        session["flow_data"] = {
            "error": "Device code has expired. Please start a new flow.",
            "flow_type": "Device Code",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        session.pop("device_code", None)
        return redirect("/")
    
    try:
        # Poll for token
        token_data = {
            "client_id": CLIENT_ID,
            "device_code": device_code,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code"
        }
        
        response = requests.post(TOKEN_ENDPOINT, data=token_data, timeout=10)
        
        # Still waiting for user
        if response.status_code == 400:
            error_response = response.json()
            error_code = error_response.get("error", "")
            
            if error_code == "authorization_pending":
                # User hasn't completed yet, show waiting message
                flow_data = session.get("flow_data", {})
                flow_data["state"] = "Waiting for user to complete authentication..."
                session["flow_data"] = flow_data
                
                # Return HTML that auto-refreshes to poll again
                return f"""
                <html>
                <head><meta http-equiv="refresh" content="5"></head>
                <body>
                    <h2>Device Code Flow - Waiting</h2>
                    <p>{flow_data.get('device_code_info', {}).get('instruction')}</p>
                    <p>Polling for completion... (auto-refreshes every 5 seconds)</p>
                    <a href="/">Back to Home</a>
                </body>
                </html>
                """
            elif error_code == "expired_token":
                session["flow_data"] = {
                    "error": "Device code has expired",
                    "flow_type": "Device Code",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                }
                session.pop("device_code", None)
                return redirect("/")
        
        if not response.ok:
            session["flow_data"] = {
                "error": f"Token request failed: {response.status_code} - {response.text}",
                "flow_type": "Device Code",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            return redirect("/")
        
        # Success!
        token_json = response.json()
        id_token = token_json.get("id_token", "")
        access_token = token_json.get("access_token", "")
        
        session["flow_data"] = {
            "flow_type": "Device Code",
            "token_response": token_json,
            "decoded_id_token": decode_jwt(id_token),
            "decoded_access_token": decode_jwt(access_token),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "state": "Completed"
        }
        
        session.pop("device_code", None)
        return redirect("/")
        
    except Exception as e:
        session["flow_data"] = {
            "error": f"Exception during polling: {str(e)}",
            "flow_type": "Device Code",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
    
    return redirect("/")


# =====================================================================
# ROUTES: OAUTH CALLBACK
# =====================================================================

@app.route("/callback")
def oauth_callback():
    """
    Callback handler for Authorization Code Flow (PKCE)
    Azure AD redirects here with authorization code
    """
    code = request.args.get("code")
    state = request.args.get("state")
    error = request.args.get("error")
    error_description = request.args.get("error_description")
    
    # Check for errors from Azure AD
    if error:
        session["flow_data"] = {
            "error": f"{error}: {error_description}",
            "flow_type": "PKCE",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        return redirect("/")
    
    # Validate state parameter (CSRF protection)
    if state != session.get("pkce_state"):
        session["flow_data"] = {
            "error": "Invalid state parameter - possible CSRF attack or session expired",
            "flow_type": "PKCE",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        return redirect("/")
    
    try:
        # Exchange authorization code for tokens
        token_data = {
            "client_id": CLIENT_ID,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": session.get("pkce_code_verifier"),
        }
        
        # Add client secret if available (recommended for web apps)
        if CLIENT_SECRET:
            token_data["client_secret"] = CLIENT_SECRET
        
        response = requests.post(TOKEN_ENDPOINT, data=token_data, timeout=10)
        
        if not response.ok:
            session["flow_data"] = {
                "error": f"Token request failed: {response.status_code} - {response.text}",
                "flow_type": "PKCE",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            return redirect("/")
        
        token_json = response.json()
        
        # Check for token errors
        if "error" in token_json:
            session["flow_data"] = {
                "error": f"{token_json.get('error')}: {token_json.get('error_description')}",
                "flow_type": "PKCE",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            return redirect("/")
        
        # Decode tokens
        id_token = token_json.get("id_token", "")
        access_token = token_json.get("access_token", "")
        
        session["flow_data"] = {
            "flow_type": "PKCE",
            "token_response": token_json,
            "decoded_id_token": decode_jwt(id_token),
            "decoded_access_token": decode_jwt(access_token),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "state": state
        }
        
    except Exception as e:
        session["flow_data"] = {
            "error": f"Exception during token exchange: {str(e)}",
            "flow_type": "PKCE",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
    
    return redirect("/")


# =====================================================================
# ERROR HANDLERS
# =====================================================================

@app.errorhandler(404)
def page_not_found(e):
    return """
    <html>
    <body style="font-family: Arial; padding: 20px;">
        <h1>404 - Page Not Found</h1>
        <p>The requested page does not exist.</p>
        <a href="/">Return to Home</a>
    </body>
    </html>
    """, 404


@app.errorhandler(500)
def server_error(e):
    return """
    <html>
    <body style="font-family: Arial; padding: 20px;">
        <h1>500 - Server Error</h1>
        <p>An error occurred: """ + str(e) + """</p>
        <a href="/">Return to Home</a>
    </body>
    </html>
    """, 500


# =====================================================================
# APPLICATION ENTRY POINT
# =====================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("OAuth 2.0 Learning Lab")
    print("=" * 60)
    print(f"Tenant ID: {TENANT_ID}")
    print(f"Client ID: {CLIENT_ID[:10]}..." if CLIENT_ID else "Client ID: NOT SET")
    print(f"Redirect URI: {REDIRECT_URI}")
    print(f"Client Secret: {'SET' if CLIENT_SECRET else 'NOT SET'}")
    print("=" * 60)
    print("Starting Flask app on http://0.0.0.0:8000")
    print("Open http://localhost:8000 in your browser")
    print("=" * 60)
    
    # Use debug=False for production
    app.run(host="0.0.0.0", port=8000, debug=False)