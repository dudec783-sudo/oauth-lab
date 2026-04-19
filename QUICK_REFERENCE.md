# Quick Reference: Testing Your OAuth Flows

## Prerequisites Checklist

- [ ] Azure AD App Registration created
- [ ] `AZURE_CLIENT_ID` recorded
- [ ] `AZURE_TENANT_ID` recorded  
- [ ] `AZURE_CLIENT_SECRET` created (if using PKCE/Client Credentials)
- [ ] Redirect URI added: `http://localhost:8000/callback`
- [ ] API permissions configured

## Quick Start

```powershell
# 1. Set environment variables
$env:AZURE_TENANT_ID = "your-tenant-id"
$env:AZURE_CLIENT_ID = "your-client-id"
$env:AZURE_CLIENT_SECRET = "your-client-secret"
$env:REDIRECT_URI = "http://localhost:8000/callback"

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run app
python app.py

# 4. Open browser
# http://localhost:8000
```

## Testing Each Flow

### Flow 1: PKCE (Authorization Code with Proof Key)

**Click:** "Start PKCE Flow"

**Expected flow:**
1. Redirected to Microsoft login
2. Sign in with Azure AD account
3. Grant permissions (if prompted)
4. Return to app with tokens

**Success indicators:**
- ✅ See "Token Response" with access_token and id_token
- ✅ ID Token shows: name, email, oid (user ID)
- ✅ Access Token shows: aud, iss, scope

**Why use PKCE:**
- Most secure for web apps
- Code never exposed in URL
- PKCE prevents interception attacks

---

### Flow 2: Client Credentials

**Click:** "Start Client Credentials Flow"

**Expected flow:**
1. No login screen
2. Immediate token response

**Success indicators:**
- ✅ See "Token Response" with access_token
- ✅ NO id_token (no user)
- ✅ Access Token shows: aud, iss, appid

**Why use Client Credentials:**
- App-to-app authentication
- No user involved
- Background jobs, services

**Note:** Requires AZURE_CLIENT_SECRET

---

### Flow 3: Device Code

**Click:** "Start Device Code Flow"

**Expected flow:**
1. See message: "Visit https://microsoft.com/devicelogin and enter code: ABC123"
2. Open URL in different browser/device
3. Enter code
4. Sign in
5. App polls and displays tokens

**Success indicators:**
- ✅ See device code information
- ✅ See polling status
- ✅ Eventually see token response

**Why use Device Code:**
- IoT devices, smart TVs, etc.
- Devices without browsers
- CLI tools

---

## Common Testing Scenarios

### Scenario 1: Debug Missing Tokens

**Problem:** Flows don't return tokens

**Debug steps:**
1. Check browser console (F12 → Console tab)
2. Check REDIRECT_URI matches Azure AD config exactly
3. Verify AZURE_CLIENT_ID is correct
4. Test with raw URL in address bar to verify REDIRECT_URI syntax

---

### Scenario 2: Test with Different User

**Steps:**
1. Go home page
2. Click "Clear & Start New Flow"
3. Sign out from Microsoft account (in another tab)
4. Try flow again with different user

---

### Scenario 3: Debug Token Content

**Steps:**
1. After successful flow, look at "Decoded ID Token"
2. Check for:
   - `"name"` - User's full name
   - `"email"` - User's email
   - `"oid"` - User's unique ID in Azure AD
3. Look at "Decoded Access Token"
4. Check for:
   - `"scope"` - Permissions granted
   - `"scp"` or `"roles"` - App permissions

---

## Environment Variables Explained

```powershell
# Your Azure AD organization
AZURE_TENANT_ID = "12345678-1234-1234-1234-123456789012"

# Your app's ID (from App Registration)
AZURE_CLIENT_ID = "87654321-4321-4321-4321-210987654321"

# Your app's secret (keep secure! Not in code!)
AZURE_CLIENT_SECRET = "abc~xyz.123.456"

# Where Azure AD sends user back after login
REDIRECT_URI = "http://localhost:8000/callback"

# Flask session encryption key
SECRET_KEY = "your-random-secret-key"
```

---

## Token Response Format

### ID Token (User Info)

```json
{
  "aud": "87654321-4321-4321-4321-210987654321",
  "iss": "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789012/v2.0",
  "iat": 1234567890,
  "exp": 1234571490,
  "name": "John Doe",
  "oid": "99999999-9999-9999-9999-999999999999",
  "preferred_username": "john@contoso.onmicrosoft.com",
  "sub": "abc123xyz"
}
```

### Access Token (Permissions)

```json
{
  "aud": "https://graph.microsoft.com",
  "iss": "https://sts.windows.net/12345678-1234-1234-1234-123456789012/",
  "iat": 1234567890,
  "exp": 1234571490,
  "appid": "87654321-4321-4321-4321-210987654321",
  "scope": "email openid profile",
  "scp": "openid profile email"
}
```

---

## Troubleshooting Quick Fixes

| Problem | Solution |
|---------|----------|
| "Invalid state" | Clear cookies, try incognito window |
| Redirect URI mismatch | Ensure exact match in Azure AD config (including http vs https) |
| Blank page after login | Check browser console for errors |
| No tokens in response | Verify AZURE_CLIENT_SECRET is correct |
| "Invalid request" | Check AZURE_CLIENT_ID and AZURE_TENANT_ID |
| Device code expired | Start new flow (codes valid ~15 minutes) |

---

## Next: Use Tokens to Call API

Once you have an access token, you can call Microsoft Graph API:

```powershell
# Get current user
$token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IuIqKlZWlpqjqjp..."
$headers = @{
    "Authorization" = "Bearer $token"
}
$response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me" -Headers $headers
Write-Host $response.displayName
```

---

## Security Reminders

🔒 **Before production:**
- ✅ Verify token signatures (use library)
- ✅ Use HTTPS everywhere
- ✅ Never commit secrets to git
- ✅ Rotate secrets regularly
- ✅ Add error logging
- ✅ Implement token refresh
- ✅ Add rate limiting
- ✅ Validate all input

---

## Still Stuck?

1. Check [SETUP_GUIDE.md](SETUP_GUIDE.md) Troubleshooting section
2. Read code comments in app.py
3. Check browser console (F12)
4. Verify all environment variables set: `Write-Host $env:AZURE_CLIENT_ID`
5. Restart Flask app
6. Try in incognito window (fresh session)

---

Good luck learning OAuth! 🚀
