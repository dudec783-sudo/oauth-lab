"""
OAuth 2.0 Learning Lab - Azure Web App Edition
Demonstrates Authorization Code, PKCE, Client Credentials, and Device Code flows
"""

from flask import Flask, redirect, request, session, render_template_string
from dotenv import load_dotenv
import requests
import os
import base64
import hashlib
import secrets
import json
import urllib.parse
import time

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-in-production")

TENANT_ID = os.environ.get("AZURE_TENANT_ID", "common")
CLIENT_ID = os.environ.get("AZURE_CLIENT_ID")
CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET")
REDIRECT_URI = os.environ.get("REDIRECT_URI", "http://localhost:8000/callback")

AUTH_ENDPOINT = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/authorize"
TOKEN_ENDPOINT = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
DEVICECODE_ENDPOINT = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/devicecode"


def decode_jwt(token):
    if not token:
        return None
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {"error": "Invalid token format"}
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception as e:
        return {"error": str(e)}


def generate_auth_url(flow_type="pkce", scope="openid profile email"):
    state = secrets.token_urlsafe(16)
    session.clear()
    session[f"{flow_type}_state"] = state
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": scope,
        "state": state,
    }
    if flow_type == "pkce":
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode().rstrip("=")
        session[f"{flow_type}_code_verifier"] = code_verifier
        session[f"{flow_type}_code_challenge"] = code_challenge
        session[f"{flow_type}_code_challenge_method"] = "S256"
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = "S256"
    query_string = "&".join([f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items()])
    return f"{AUTH_ENDPOINT}?{query_string}"


def format_json(data):
    try:
        return json.dumps(data, indent=2)
    except:
        return str(data)


def normalize_localhost_for_session():
    parsed = urllib.parse.urlparse(REDIRECT_URI)
    configured_host = parsed.hostname
    configured_netloc = parsed.netloc
    current_host = request.host.split(":")[0]
    local_hosts = {"localhost", "127.0.0.1"}
    if configured_host in local_hosts and current_host in local_hosts and current_host != configured_host:
        target = request.url.replace(
            f"{request.scheme}://{request.host}",
            f"{request.scheme}://{configured_netloc}", 1
        )
        return redirect(target)
    return None


BASE_STYLES = """
@import url('https://fonts.googleapis.com/css2?family=Space+Mono:ital,wght@0,400;0,700;1,400&family=Syne:wght@400;600;700;800&display=swap');

:root {
  --bg: #0a0c10;
  --surface: #10141c;
  --surface2: #161b26;
  --border: #1e2736;
  --accent: #00d4ff;
  --accent2: #7c3aed;
  --accent3: #10b981;
  --warn: #f59e0b;
  --danger: #ef4444;
  --text: #e2e8f0;
  --text-dim: #64748b;
  --text-muted: #334155;
  --glow: rgba(0,212,255,0.15);
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: 'Space Mono', monospace;
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  overflow-x: hidden;
}

body::before {
  content: '';
  position: fixed;
  inset: 0;
  background:
    radial-gradient(ellipse 80% 50% at 20% 0%, rgba(0,212,255,0.06) 0%, transparent 60%),
    radial-gradient(ellipse 60% 40% at 80% 100%, rgba(124,58,237,0.07) 0%, transparent 60%);
  pointer-events: none;
  z-index: 0;
}

.grid-overlay {
  position: fixed;
  inset: 0;
  background-image:
    linear-gradient(rgba(0,212,255,0.03) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0,212,255,0.03) 1px, transparent 1px);
  background-size: 40px 40px;
  pointer-events: none;
  z-index: 0;
}

.wrapper {
  position: relative;
  z-index: 1;
  max-width: 1100px;
  margin: 0 auto;
  padding: 40px 24px 80px;
}

/* ── HEADER ── */
.header {
  display: flex;
  align-items: center;
  gap: 16px;
  margin-bottom: 48px;
  padding-bottom: 24px;
  border-bottom: 1px solid var(--border);
}

.logo-mark {
  width: 48px; height: 48px;
  background: linear-gradient(135deg, var(--accent), var(--accent2));
  border-radius: 12px;
  display: flex; align-items: center; justify-content: center;
  font-size: 22px;
  flex-shrink: 0;
  box-shadow: 0 0 24px rgba(0,212,255,0.3);
}

.header-text h1 {
  font-family: 'Syne', sans-serif;
  font-size: 1.6rem;
  font-weight: 800;
  letter-spacing: -0.02em;
  color: var(--text);
}

.header-text p {
  font-size: 0.72rem;
  color: var(--text-dim);
  margin-top: 2px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.badge {
  margin-left: auto;
  font-size: 0.65rem;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: var(--accent);
  border: 1px solid rgba(0,212,255,0.3);
  padding: 4px 10px;
  border-radius: 4px;
  background: rgba(0,212,255,0.06);
}

/* ── CONFIG BANNER ── */
.config-banner {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 16px 20px;
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 12px;
  margin-bottom: 36px;
}

.config-item {
  display: flex;
  flex-direction: column;
  gap: 3px;
}

.config-label {
  font-size: 0.6rem;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  color: var(--text-dim);
}

.config-value {
  font-size: 0.78rem;
  color: var(--accent);
  word-break: break-all;
}

.config-dot {
  display: inline-block;
  width: 7px; height: 7px;
  border-radius: 50%;
  background: var(--accent3);
  margin-right: 6px;
  box-shadow: 0 0 6px var(--accent3);
  animation: pulse 2s ease infinite;
}

@keyframes pulse {
  0%,100% { opacity:1; }
  50% { opacity:0.4; }
}

/* ── SECTION TITLE ── */
.section-title {
  font-family: 'Syne', sans-serif;
  font-size: 0.65rem;
  font-weight: 700;
  letter-spacing: 0.2em;
  text-transform: uppercase;
  color: var(--text-dim);
  margin-bottom: 16px;
  display: flex;
  align-items: center;
  gap: 10px;
}

.section-title::after {
  content: '';
  flex: 1;
  height: 1px;
  background: var(--border);
}

/* ── FLOW CARDS ── */
.flows-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 16px;
  margin-bottom: 40px;
}

.flow-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 24px;
  transition: border-color 0.2s, transform 0.2s;
  position: relative;
  overflow: hidden;
}

.flow-card::before {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 2px;
  background: linear-gradient(90deg, transparent, var(--card-accent, var(--accent)), transparent);
  opacity: 0;
  transition: opacity 0.2s;
}

.flow-card:hover {
  border-color: var(--card-accent, var(--accent));
  transform: translateY(-2px);
}

.flow-card:hover::before { opacity: 1; }

.flow-card.pkce { --card-accent: var(--accent); }
.flow-card.client { --card-accent: var(--accent2); }
.flow-card.device { --card-accent: var(--accent3); }

.flow-icon {
  font-size: 1.5rem;
  margin-bottom: 14px;
}

.flow-num {
  font-size: 0.6rem;
  letter-spacing: 0.15em;
  text-transform: uppercase;
  color: var(--card-accent, var(--accent));
  margin-bottom: 6px;
}

.flow-name {
  font-family: 'Syne', sans-serif;
  font-size: 1rem;
  font-weight: 700;
  color: var(--text);
  margin-bottom: 8px;
}

.flow-desc {
  font-size: 0.72rem;
  color: var(--text-dim);
  line-height: 1.6;
  margin-bottom: 16px;
}

.flow-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-bottom: 20px;
}

.tag {
  font-size: 0.6rem;
  padding: 3px 8px;
  border-radius: 3px;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  background: var(--surface2);
  color: var(--text-dim);
  border: 1px solid var(--border);
}

.btn {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 9px 18px;
  border-radius: 6px;
  font-family: 'Space Mono', monospace;
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  cursor: pointer;
  text-decoration: none;
  border: none;
  transition: all 0.15s;
}

.btn-primary {
  background: var(--card-accent, var(--accent));
  color: #000;
}

.btn-primary:hover {
  filter: brightness(1.15);
  transform: translateY(-1px);
}

.btn-ghost {
  background: transparent;
  color: var(--text-dim);
  border: 1px solid var(--border);
}

.btn-ghost:hover {
  border-color: var(--accent);
  color: var(--accent);
}

/* ── RESULTS SECTION ── */
.results-section {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  overflow: hidden;
  margin-bottom: 40px;
}

.results-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 24px;
  border-bottom: 1px solid var(--border);
  background: var(--surface2);
}

.results-title {
  font-family: 'Syne', sans-serif;
  font-size: 0.85rem;
  font-weight: 700;
  display: flex;
  align-items: center;
  gap: 10px;
}

.flow-pill {
  font-size: 0.6rem;
  padding: 3px 10px;
  border-radius: 20px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  font-weight: 700;
}

.pill-pkce { background: rgba(0,212,255,0.15); color: var(--accent); }
.pill-client { background: rgba(124,58,237,0.15); color: #a78bfa; }
.pill-device { background: rgba(16,185,129,0.15); color: var(--accent3); }
.pill-unknown { background: rgba(100,116,139,0.15); color: var(--text-dim); }

.results-meta {
  font-size: 0.65rem;
  color: var(--text-dim);
}

/* ── ALERTS ── */
.alert {
  margin: 20px 24px;
  padding: 12px 16px;
  border-radius: 8px;
  font-size: 0.75rem;
  display: flex;
  align-items: flex-start;
  gap: 10px;
}

.alert-icon { font-size: 1rem; flex-shrink: 0; margin-top: 1px; }

.alert-error {
  background: rgba(239,68,68,0.08);
  border: 1px solid rgba(239,68,68,0.25);
  color: #fca5a5;
}

.alert-success {
  background: rgba(16,185,129,0.08);
  border: 1px solid rgba(16,185,129,0.25);
  color: #6ee7b7;
}

.alert-info {
  background: rgba(0,212,255,0.06);
  border: 1px solid rgba(0,212,255,0.2);
  color: var(--accent);
}

/* ── DATA PANELS ── */
.data-panels {
  padding: 0 24px 24px;
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.data-panel {
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
}

.panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 14px;
  background: var(--surface2);
  cursor: pointer;
  user-select: none;
  gap: 10px;
}

.panel-header-left {
  display: flex;
  align-items: center;
  gap: 10px;
}

.panel-dot {
  width: 8px; height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}

.dot-raw { background: var(--warn); box-shadow: 0 0 6px var(--warn); }
.dot-id { background: var(--accent); box-shadow: 0 0 6px var(--accent); }
.dot-access { background: var(--accent2); box-shadow: 0 0 6px var(--accent2); }
.dot-details { background: var(--accent3); box-shadow: 0 0 6px var(--accent3); }

.panel-label {
  font-size: 0.68rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--text);
}

.panel-chevron {
  color: var(--text-dim);
  font-size: 0.75rem;
  transition: transform 0.2s;
}

.panel-body {
  background: #0d1117;
  max-height: 400px;
  overflow: auto;
}

.panel-body pre {
  padding: 16px;
  font-family: 'Space Mono', monospace;
  font-size: 0.7rem;
  line-height: 1.7;
  color: #c9d1d9;
  white-space: pre-wrap;
  word-break: break-word;
}

/* JSON syntax highlighting */
.json-key { color: #79c0ff; }
.json-str { color: #a5d6ff; }
.json-num { color: #ffa657; }
.json-bool { color: #ff7b72; }
.json-null { color: #8b949e; }

/* ── META ROW ── */
.meta-row {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 1px;
  background: var(--border);
  border-top: 1px solid var(--border);
}

.meta-cell {
  background: var(--surface2);
  padding: 10px 16px;
}

.meta-cell-label {
  font-size: 0.58rem;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  color: var(--text-muted);
  margin-bottom: 3px;
}

.meta-cell-value {
  font-size: 0.7rem;
  color: var(--text-dim);
  word-break: break-all;
}

/* ── DEVICE CODE SPECIAL ── */
.device-waiting {
  padding: 24px;
  text-align: center;
}

.device-code-box {
  display: inline-flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
  background: var(--surface2);
  border: 2px dashed rgba(16,185,129,0.4);
  border-radius: 12px;
  padding: 28px 40px;
  margin: 16px auto;
}

.device-user-code {
  font-family: 'Syne', sans-serif;
  font-size: 2rem;
  font-weight: 800;
  letter-spacing: 0.15em;
  color: var(--accent3);
  text-shadow: 0 0 20px rgba(16,185,129,0.4);
}

.device-url {
  font-size: 0.75rem;
  color: var(--accent);
}

.spinner {
  display: inline-block;
  width: 14px; height: 14px;
  border: 2px solid var(--border);
  border-top-color: var(--accent3);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
  vertical-align: middle;
  margin-right: 6px;
}

@keyframes spin { to { transform: rotate(360deg); } }

/* ── SETUP SECTION ── */
.setup-section {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  overflow: hidden;
}

.setup-header {
  padding: 16px 24px;
  border-bottom: 1px solid var(--border);
  background: var(--surface2);
  font-family: 'Syne', sans-serif;
  font-size: 0.85rem;
  font-weight: 700;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.setup-body {
  padding: 24px;
  display: none;
}

.setup-body.open { display: block; }

.code-block {
  background: #0d1117;
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 14px 16px;
  font-size: 0.7rem;
  line-height: 1.8;
  color: #c9d1d9;
  margin: 10px 0;
  overflow-x: auto;
}

.code-comment { color: #8b949e; }
.code-key { color: #ff7b72; }
.code-val { color: #a5d6ff; }

ol, ul { padding-left: 20px; }
ol li, ul li {
  font-size: 0.75rem;
  color: var(--text-dim);
  margin-bottom: 8px;
  line-height: 1.6;
}

.footer {
  text-align: center;
  font-size: 0.65rem;
  color: var(--text-muted);
  letter-spacing: 0.08em;
  padding-top: 40px;
  border-top: 1px solid var(--border);
  margin-top: 40px;
}
"""

HIGHLIGHT_JS = """
function syntaxHighlight(json) {
  if (typeof json !== 'string') {
    json = JSON.stringify(json, null, 2);
  }
  return json.replace(/("(\\\\u[a-zA-Z0-9]{4}|\\\\[^u]|[^\\\\"])*"(\\s*:)?|\\b(true|false|null)\\b|-?\\d+(?:\\.\\d*)?(?:[eE][+\\-]?\\d+)?)/g, function(match) {
    let cls = 'json-num';
    if (/^"/.test(match)) {
      cls = /:$/.test(match) ? 'json-key' : 'json-str';
    } else if (/true|false/.test(match)) {
      cls = 'json-bool';
    } else if (/null/.test(match)) {
      cls = 'json-null';
    }
    return '<span class="' + cls + '">' + match + '</span>';
  });
}

document.addEventListener('DOMContentLoaded', function() {
  document.querySelectorAll('.json-pre').forEach(function(el) {
    el.innerHTML = syntaxHighlight(el.textContent);
  });

  document.querySelectorAll('.panel-header').forEach(function(h) {
    h.addEventListener('click', function() {
      const body = this.nextElementSibling;
      const chevron = this.querySelector('.panel-chevron');
      const isOpen = body.style.display === 'block';
      body.style.display = isOpen ? 'none' : 'block';
      if (chevron) chevron.textContent = isOpen ? '▶' : '▼';
    });
  });

  document.querySelectorAll('.setup-header').forEach(function(h) {
    h.addEventListener('click', function() {
      const body = this.nextElementSibling;
      body.classList.toggle('open');
      const ch = this.querySelector('.setup-chevron');
      if (ch) ch.textContent = body.classList.contains('open') ? '▼' : '▶';
    });
  });
});
"""


def get_pill_class(flow_type):
    ft = (flow_type or "").lower()
    if "pkce" in ft or "authorization" in ft:
        return "pill-pkce"
    if "client" in ft:
        return "pill-client"
    if "device" in ft:
        return "pill-device"
    return "pill-unknown"


def build_page(content, extra_head=""):
    client_id_display = (CLIENT_ID[:8] + "···" + CLIENT_ID[-4:]) if CLIENT_ID and len(CLIENT_ID) > 12 else (CLIENT_ID or "NOT SET")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OAuth 2.0 Lab · Azure AD</title>
{extra_head}
<style>{BASE_STYLES}</style>
</head>
<body>
<div class="grid-overlay"></div>
<div class="wrapper">

  <header class="header">
    <div class="logo-mark">🔐</div>
    <div class="header-text">
      <h1>OAuth 2.0 Learning Lab</h1>
      <p>Microsoft Entra ID · Raw Token Inspector</p>
    </div>
    <span class="badge">Azure AD</span>
  </header>

  <div class="config-banner">
    <div class="config-item">
      <span class="config-label">Tenant ID</span>
      <span class="config-value"><span class="config-dot"></span>{TENANT_ID}</span>
    </div>
    <div class="config-item">
      <span class="config-label">Client ID</span>
      <span class="config-value">{client_id_display}</span>
    </div>
    <div class="config-item">
      <span class="config-label">Redirect URI</span>
      <span class="config-value">{REDIRECT_URI}</span>
    </div>
    <div class="config-item">
      <span class="config-label">Client Secret</span>
      <span class="config-value">{"✓ configured" if CLIENT_SECRET else "✗ not set"}</span>
    </div>
  </div>

  {content}

  <div class="setup-section">
    <div class="setup-header">
      ⚙ Setup & Environment Guide <span class="setup-chevron">▶</span>
    </div>
    <div class="setup-body">
      <p style="font-size:0.75rem;color:var(--text-dim);margin-bottom:16px;">Required environment variables and Azure AD App Registration steps.</p>
      <div class="code-block"><span class="code-comment"># .env file</span>
<span class="code-key">AZURE_TENANT_ID</span>=<span class="code-val">your-tenant-id-or-common</span>
<span class="code-key">AZURE_CLIENT_ID</span>=<span class="code-val">xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx</span>
<span class="code-key">AZURE_CLIENT_SECRET</span>=<span class="code-val">your~client~secret~value</span>
<span class="code-key">REDIRECT_URI</span>=<span class="code-val">https://your-app.azurewebsites.net/callback</span>
<span class="code-key">SECRET_KEY</span>=<span class="code-val">generate-a-random-secret</span></div>
      <ol style="margin-top:16px;">
        <li>Azure Portal → <strong style="color:var(--text)">Microsoft Entra ID</strong> → App registrations → New registration</li>
        <li>Copy <strong style="color:var(--text)">Application (client) ID</strong> → set as AZURE_CLIENT_ID</li>
        <li>Certificates &amp; secrets → New client secret → copy value → AZURE_CLIENT_SECRET</li>
        <li>Authentication → Add platform → Web → set Redirect URI → check ID tokens &amp; Access tokens</li>
        <li>API permissions → Add → Microsoft Graph → Delegated → <code>openid profile email User.Read</code></li>
        <li>For Client Credentials: API permissions → Application permissions → grant admin consent</li>
      </ol>
    </div>
  </div>

  <div class="footer">OAuth 2.0 Learning Lab · Educational Use · Always verify token signatures in production</div>
</div>
<script>{HIGHLIGHT_JS}</script>
</body>
</html>"""


def build_results_block(flow_data, waiting=False):
    ft = flow_data.get("flow_type", "Unknown")
    pill = get_pill_class(ft)
    ts = flow_data.get("timestamp", "")
    state = flow_data.get("state", "N/A")

    alert_html = ""
    if flow_data.get("error"):
        alert_html = f"""<div class="alert alert-error">
          <span class="alert-icon">✗</span>
          <div><strong>Error:</strong> {flow_data.get("error")}</div>
        </div>"""
    elif waiting:
        device_info = flow_data.get("device_code_info", {})
        user_code = device_info.get("user_code", "")
        url = device_info.get("verification_uri", "https://microsoft.com/devicelogin")
        alert_html = f"""<div class="device-waiting">
          <p style="font-size:0.75rem;color:var(--text-dim);margin-bottom:12px;">
            <span class="spinner"></span>Waiting for user authentication on another device…
          </p>
          <div class="device-code-box">
            <div style="font-size:0.65rem;text-transform:uppercase;letter-spacing:0.15em;color:var(--text-dim)">Enter code at</div>
            <a href="{url}" target="_blank" class="device-url">{url}</a>
            <div class="device-user-code">{user_code}</div>
          </div>
          <p style="font-size:0.65rem;color:var(--text-muted);margin-top:8px;">Page refreshes automatically every 5 seconds</p>
        </div>"""
    else:
        alert_html = """<div class="alert alert-success">
          <span class="alert-icon">✓</span>
          <div><strong>Success!</strong> Tokens received and decoded below.</div>
        </div>"""

    def make_panel(dot_cls, label, data, open_default=True):
        if not data:
            return ""
        formatted = format_json(data)
        display = "block" if open_default else "none"
        chevron = "▼" if open_default else "▶"
        return f"""<div class="data-panel">
          <div class="panel-header">
            <div class="panel-header-left">
              <span class="panel-dot {dot_cls}"></span>
              <span class="panel-label">{label}</span>
            </div>
            <span class="panel-chevron">{chevron}</span>
          </div>
          <div class="panel-body" style="display:{display}">
            <pre class="json-pre">{formatted}</pre>
          </div>
        </div>"""

    panels = ""

    # ── User Login Identity (PKCE only) ──────────────────────────────
    if flow_data.get("user_identity"):
        ui = flow_data["user_identity"]
        panels += f"""<div class="data-panel">
          <div class="panel-header" style="cursor:default">
            <div class="panel-header-left">
              <span class="panel-dot" style="background:var(--accent);box-shadow:0 0 6px var(--accent)"></span>
              <span class="panel-label">👤 User Login — Identity Claims</span>
            </div>
          </div>
          <div class="panel-body" style="display:block">
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:1px;background:var(--border)">
              {"".join(f'''<div style="background:#0d1117;padding:12px 16px">
                <div style="font-size:0.58rem;text-transform:uppercase;letter-spacing:0.12em;color:var(--text-muted);margin-bottom:4px">{k.replace("_"," ").title()}</div>
                <div style="font-size:0.75rem;color:var(--accent);word-break:break-all;font-family:'Space Mono',monospace">{v if v else '<span style="color:var(--text-muted)">—</span>'}</div>
              </div>''' for k,v in ui.items() if v)}
            </div>
          </div>
        </div>"""

    # ── PKCE S256 Parameters ─────────────────────────────────────────
    if flow_data.get("pkce_details"):
        pd = flow_data["pkce_details"]
        panels += f"""<div class="data-panel">
          <div class="panel-header" style="cursor:default">
            <div class="panel-header-left">
              <span class="panel-dot" style="background:var(--warn);box-shadow:0 0 6px var(--warn)"></span>
              <span class="panel-label">🔑 PKCE S256 — Flow Parameters</span>
            </div>
          </div>
          <div class="panel-body" style="display:block">
            <div style="display:grid;grid-template-columns:1fr;gap:1px;background:var(--border)">
              {"".join(f'''<div style="background:#0d1117;padding:10px 16px;display:grid;grid-template-columns:220px 1fr;gap:12px;align-items:start">
                <div style="font-size:0.62rem;text-transform:uppercase;letter-spacing:0.1em;color:var(--text-dim);padding-top:2px">{k.lstrip("0123456789_").replace("_"," ").title()}</div>
                <div style="font-size:0.7rem;color:#ffa657;word-break:break-all;font-family:'Space Mono',monospace">{v}</div>
              </div>''' for k,v in pd.items())}
            </div>
          </div>
        </div>"""

    # ── Raw Token Response ────────────────────────────────────────────
    panels += make_panel("dot-raw", "📄 Raw Token Response — Full JSON from Azure AD", flow_data.get("token_response"), open_default=True)

    # ── Decoded ID Token ──────────────────────────────────────────────
    panels += make_panel("dot-id", "🪪 Decoded ID Token — User Identity Claims (JWT payload)", flow_data.get("decoded_id_token"), open_default=True)

    # ── Decoded Access Token ──────────────────────────────────────────
    panels += make_panel("dot-access", "🔓 Decoded Access Token — Permissions & Scopes (JWT payload)", flow_data.get("decoded_access_token"), open_default=True)

    # ── Device Code info / raw details fallback ───────────────────────
    extra = {}
    if flow_data.get("raw_details"): extra.update(flow_data["raw_details"])
    if flow_data.get("device_code_info"): extra["device_code_info"] = flow_data["device_code_info"]
    if extra:
        panels += make_panel("dot-details", "⚙ Additional Flow Details", extra, open_default=True)

    return f"""<div class="results-section" style="margin-bottom:28px;">
      <div class="results-header">
        <div class="results-title">
          Flow Results
          <span class="flow-pill {pill}">{ft}</span>
        </div>
        <div class="results-meta">{ts}</div>
      </div>
      {alert_html}
      <div class="data-panels">{panels}</div>
      <div class="meta-row">
        <div class="meta-cell">
          <div class="meta-cell-label">Flow Type</div>
          <div class="meta-cell-value">{ft}</div>
        </div>
        <div class="meta-cell">
          <div class="meta-cell-label">State</div>
          <div class="meta-cell-value">{state}</div>
        </div>
        <div class="meta-cell">
          <div class="meta-cell-label">Timestamp</div>
          <div class="meta-cell-value">{ts}</div>
        </div>
        <div class="meta-cell">
          <div class="meta-cell-label">Actions</div>
          <div class="meta-cell-value">
            <a href="/clear" class="btn btn-ghost" style="padding:4px 10px;font-size:0.62rem;">✕ Clear</a>
          </div>
        </div>
      </div>
    </div>"""


HOME_FLOWS = """
<div class="section-title">Available Flows</div>

<div class="flows-grid">

  <div class="flow-card pkce">
    <div class="flow-icon">🔑</div>
    <div class="flow-num">Flow 01</div>
    <div class="flow-name">Authorization Code + PKCE</div>
    <div class="flow-desc">Most secure web flow. Generates a code_challenge (S256), redirects user to Microsoft login, then exchanges the authorization code for tokens using the code_verifier.</div>
    <div class="flow-tags">
      <span class="tag">User Login</span>
      <span class="tag">PKCE S256</span>
      <span class="tag">ID Token</span>
      <span class="tag">Access Token</span>
    </div>
    <a href="/pkce/start" class="btn btn-primary" style="--card-accent:var(--accent)">▶ Start PKCE Flow</a>
  </div>

  <div class="flow-card client">
    <div class="flow-icon">🤖</div>
    <div class="flow-num">Flow 02</div>
    <div class="flow-name">Client Credentials</div>
    <div class="flow-desc">Server-to-server authentication with no user interaction. The app sends Client ID + Secret directly to Azure AD and receives an access token scoped to application permissions.</div>
    <div class="flow-tags">
      <span class="tag">No User</span>
      <span class="tag">Client Secret</span>
      <span class="tag">App Permissions</span>
    </div>
    <a href="/clientcreds/start" class="btn btn-primary" style="--card-accent:var(--accent2);color:#fff">▶ Start Client Credentials</a>
  </div>

  <div class="flow-card device">
    <div class="flow-icon">📱</div>
    <div class="flow-num">Flow 03</div>
    <div class="flow-name">Device Code</div>
    <div class="flow-desc">For devices without a browser. Azure AD returns a user code; the user authenticates on another device at microsoft.com/devicelogin. The server polls until authentication completes.</div>
    <div class="flow-tags">
      <span class="tag">CLI / IoT</span>
      <span class="tag">Polling</span>
      <span class="tag">No Browser</span>
    </div>
    <a href="/device/start" class="btn btn-primary" style="--card-accent:var(--accent3);color:#000">▶ Start Device Code</a>
  </div>

</div>
"""


@app.route("/")
def home():
    normalized = normalize_localhost_for_session()
    if normalized:
        return normalized

    flow_data = session.get("flow_data")
    results = build_results_block(flow_data) if flow_data else ""

    content = HOME_FLOWS + results
    return build_page(content)


@app.route("/clear")
def clear_flow_data():
    session.clear()
    return redirect("/")


@app.route("/pkce/start")
def pkce_start():
    normalized = normalize_localhost_for_session()
    if normalized:
        return normalized
    try:
        auth_url = generate_auth_url(flow_type="pkce", scope="openid profile email offline_access")
        session["pkce_debug"] = {
            "step": "authorization_redirect",
            "state_generated": session.get("pkce_state"),
            "pkce_code_verifier": session.get("pkce_code_verifier"),
            "pkce_code_challenge": session.get("pkce_code_challenge"),
            "pkce_code_challenge_method": session.get("pkce_code_challenge_method"),
            "redirect_uri": REDIRECT_URI,
            "scope": "openid profile email offline_access"
        }
        return redirect(auth_url)
    except Exception as e:
        session["flow_data"] = {"error": f"Failed to start PKCE flow: {str(e)}", "flow_type": "PKCE"}
        return redirect("/")


@app.route("/clientcreds/start")
def clientcreds_start():
    if not CLIENT_SECRET:
        session["flow_data"] = {
            "error": "Client Credentials flow requires AZURE_CLIENT_SECRET environment variable",
            "flow_type": "Client Credentials"
        }
        return redirect("/")
    try:
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
        flow_data = {
            "flow_type": "Client Credentials",
            "token_response": token_json,
            "decoded_access_token": decode_jwt(token_json.get("access_token", "")),
            "decoded_id_token": None,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "state": "N/A (no user interaction)"
        }
        return build_page(HOME_FLOWS + build_results_block(flow_data))
    except Exception as e:
        flow_data = {
            "error": f"Exception during Client Credentials flow: {str(e)}",
            "flow_type": "Client Credentials"
        }
        return build_page(HOME_FLOWS + build_results_block(flow_data))


@app.route("/device/start")
def device_start():
    try:
        device_data = {"client_id": CLIENT_ID, "scope": "openid profile email offline_access"}
        response = requests.post(DEVICECODE_ENDPOINT, data=device_data, timeout=10)
        if not response.ok:
            session["flow_data"] = {
                "error": f"Device code request failed: {response.status_code} - {response.text}",
                "flow_type": "Device Code",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            return redirect("/")
        device_json = response.json()
        session["device_code"] = device_json.get("device_code")
        session["device_polling_start"] = time.time()
        session["device_polling_expires"] = device_json.get("expires_in", 900)
        session["device_polling_interval"] = device_json.get("interval", 5)
        session["flow_data"] = {
            "flow_type": "Device Code",
            "device_code_info": {
                "user_code": device_json.get("user_code"),
                "verification_uri": device_json.get("verification_uri"),
                "expires_in": device_json.get("expires_in", 900)
            },
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "state": "Waiting for user authentication…"
        }
        return redirect("/device/poll")
    except Exception as e:
        session["flow_data"] = {
            "error": f"Exception during Device Code flow: {str(e)}",
            "flow_type": "Device Code"
        }
    return redirect("/")


@app.route("/device/poll")
def device_poll():
    device_code = session.get("device_code")
    polling_start = session.get("device_polling_start", 0)
    polling_expires = session.get("device_polling_expires", 900)

    if not device_code:
        return redirect("/")

    if time.time() - polling_start > polling_expires:
        session["flow_data"] = {
            "error": "Device code has expired. Please start a new flow.",
            "flow_type": "Device Code",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        session.pop("device_code", None)
        return redirect("/")

    try:
        token_data = {
            "client_id": CLIENT_ID,
            "device_code": device_code,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code"
        }
        if CLIENT_SECRET:
            token_data["client_secret"] = CLIENT_SECRET

        response = requests.post(TOKEN_ENDPOINT, data=token_data, timeout=10)

        if response.status_code == 400:
            error_code = response.json().get("error", "")
            if error_code == "authorization_pending":
                flow_data = session.get("flow_data", {})
                flow_data["state"] = "Waiting for user to complete authentication…"
                session["flow_data"] = flow_data
                results = build_results_block(flow_data, waiting=True)
                content = HOME_FLOWS + results
                page = build_page(content, extra_head='<meta http-equiv="refresh" content="5">')
                return page
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

        token_json = response.json()
        for k in ["device_code", "device_polling_start", "device_polling_expires", "device_polling_interval"]:
            session.pop(k, None)
        decoded_id = decode_jwt(token_json.get("id_token", ""))
        decoded_access = decode_jwt(token_json.get("access_token", ""))
        user_identity = None
        if decoded_id and "error" not in decoded_id:
            user_identity = {
                "name": decoded_id.get("name"),
                "email": decoded_id.get("email") or decoded_id.get("preferred_username"),
                "upn": decoded_id.get("upn") or decoded_id.get("preferred_username"),
                "oid": decoded_id.get("oid"),
                "tenant_id": decoded_id.get("tid"),
                "issued_at": decoded_id.get("iat"),
                "expires_at": decoded_id.get("exp"),
            }
        flow_data = {
            "flow_type": "Device Code",
            "token_response": token_json,
            "decoded_id_token": decoded_id,
            "decoded_access_token": decoded_access,
            "user_identity": user_identity,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "state": "Authentication completed via device code"
        }
        return build_page(HOME_FLOWS + build_results_block(flow_data))

    except Exception as e:
        flow_data = {
            "error": f"Exception during polling: {str(e)}",
            "flow_type": "Device Code",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        return build_page(HOME_FLOWS + build_results_block(flow_data))


@app.route("/callback")
def oauth_callback():
    code = request.args.get("code")
    state = request.args.get("state")
    error = request.args.get("error")
    error_description = request.args.get("error_description")
    pkce_debug = session.get("pkce_debug", {})
    pkce_debug.update({
        "callback_state": state,
        "session_state": session.get("pkce_state"),
        "authorization_code_received": bool(code)
    })
    session["pkce_debug"] = pkce_debug

    if error:
        session["flow_data"] = {
            "error": f"{error}: {error_description}",
            "flow_type": "PKCE",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "raw_details": {
                "error_from_provider": error,
                "error_description_from_provider": error_description,
                "state_from_callback": state,
                "state_from_session": session.get("pkce_state"),
            }
        }
        return redirect("/")

    session_state = session.get("pkce_state")
    if state != session_state:
        session["flow_data"] = {
            "error": "Invalid state parameter — possible CSRF attack or session expired",
            "flow_type": "PKCE",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "raw_details": {
                "state_from_url": state,
                "state_from_session": session_state,
            }
        }
        session.pop("pkce_state", None)
        session.pop("pkce_code_verifier", None)
        return redirect("/")

    # Read PKCE values from session BEFORE clearing — these are small and survive the redirect
    code_verifier  = session.get("pkce_code_verifier")
    code_challenge = session.get("pkce_code_challenge")
    code_challenge_method = session.get("pkce_code_challenge_method", "S256")
    for k in ["pkce_state", "pkce_code_verifier", "pkce_code_challenge", "pkce_code_challenge_method", "pkce_debug"]:
        session.pop(k, None)

    try:
        token_data = {
            "client_id": CLIENT_ID,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": code_verifier,
        }
        if CLIENT_SECRET:
            token_data["client_secret"] = CLIENT_SECRET

        response = requests.post(TOKEN_ENDPOINT, data=token_data, timeout=10)

        if not response.ok:
            flow_data = {
                "error": f"Token request failed: {response.status_code} — {response.text}",
                "flow_type": "PKCE",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "pkce_details": {
                    "pkce_code_verifier": code_verifier,
                    "pkce_code_challenge": code_challenge,
                    "pkce_code_challenge_method": code_challenge_method,
                    "state_from_callback": state,
                    "redirect_uri": REDIRECT_URI,
                }
            }
            return build_page(HOME_FLOWS + build_results_block(flow_data))

        token_json = response.json()
        if "error" in token_json:
            flow_data = {
                "error": f"{token_json.get('error')}: {token_json.get('error_description')}",
                "flow_type": "PKCE",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "pkce_details": {"provider_error_detail": token_json}
            }
            return build_page(HOME_FLOWS + build_results_block(flow_data))

        # ── Decode tokens ────────────────────────────────────────────
        decoded_id     = decode_jwt(token_json.get("id_token", ""))
        decoded_access = decode_jwt(token_json.get("access_token", ""))

        # ── User identity summary from ID token ──────────────────────
        user_identity = None
        if decoded_id and "error" not in decoded_id:
            user_identity = {
                "name":       decoded_id.get("name"),
                "email":      decoded_id.get("email") or decoded_id.get("preferred_username"),
                "upn":        decoded_id.get("upn")   or decoded_id.get("preferred_username"),
                "oid":        decoded_id.get("oid"),
                "tenant_id":  decoded_id.get("tid"),
                "issued_at":  decoded_id.get("iat"),
                "expires_at": decoded_id.get("exp"),
                "issuer":     decoded_id.get("iss"),
                "audience":   decoded_id.get("aud"),
            }

        # ── PKCE parameters panel ─────────────────────────────────────
        pkce_details = {
            "flow_type":               "Authorization Code + PKCE (S256)",
            "grant_type":              "authorization_code",
            "scope":                   "openid profile email offline_access",
            "pkce_code_verifier":      code_verifier  or "(session key not found)",
            "pkce_code_challenge":     code_challenge or "(session key not found)",
            "pkce_code_challenge_method": code_challenge_method,
            "state_from_callback":     state,
            "state_validated":         True,
            "authorization_code_received": bool(code),
            "redirect_uri":            REDIRECT_URI,
            "token_endpoint":          TOKEN_ENDPOINT,
            "auth_endpoint":           AUTH_ENDPOINT,
        }

        flow_data = {
            "flow_type":            "PKCE",
            "token_response":       token_json,
            "decoded_id_token":     decoded_id,
            "decoded_access_token": decoded_access,
            "user_identity":        user_identity,
            "pkce_details":         pkce_details,
            "timestamp":            time.strftime("%Y-%m-%d %H:%M:%S"),
            "state":                state,
        }
        # Render directly — no session storage needed, avoids 4KB cookie limit
        return build_page(HOME_FLOWS + build_results_block(flow_data))

    except Exception as e:
        flow_data = {
            "error": f"Exception during token exchange: {str(e)}",
            "flow_type": "PKCE",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        return build_page(HOME_FLOWS + build_results_block(flow_data))


if __name__ == "__main__":
    if not CLIENT_ID:
        raise ValueError("AZURE_CLIENT_ID environment variable is required")
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="127.0.0.1", port=port, debug=True)
