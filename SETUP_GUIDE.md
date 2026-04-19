# OAuth 2.0 Learning Lab - Complete Setup Guide

A comprehensive Flask application demonstrating OAuth 2.0 flows with Microsoft Entra ID (Azure AD).

## Table of Contents
1. [Features](#features)
2. [Prerequisites](#prerequisites)
3. [Azure AD App Registration](#azure-ad-app-registration)
4. [Local Development Setup](#local-development-setup)
5. [Environment Variables](#environment-variables)
6. [Testing Each Flow](#testing-each-flow)
7. [Deploying to Azure App Service](#deploying-to-azure-app-service)
8. [Troubleshooting](#troubleshooting)

---

## Features

✅ **Authorization Code Flow with PKCE** - Most secure web app flow
✅ **Client Credentials Flow** - Server-to-server authentication  
✅ **Device Code Flow** - For devices without browsers
✅ **Token Decoding** - View JWT claims without verification
✅ **Raw Token Display** - See complete token responses
✅ **Error Handling** - Clear error messages for debugging
✅ **Production Ready** - Works with gunicorn on Azure App Service
✅ **Beginner Friendly** - Well-commented code with clear explanations

---

## Prerequisites

- Python 3.9 or higher
- Git
- Azure subscription with access to Microsoft Entra ID
- Text editor or IDE

---

## Azure AD App Registration

### Step 1: Create App Registration

1. Go to [Azure Portal](https://portal.azure.com)
2. Search for **"Microsoft Entra ID"** (or "Azure Active Directory")
3. Click **"App registrations"** → **"New registration"**
4. **Name:** `OAuth Lab`
5. **Supported account types:** Select your preferred option:
   - "Accounts in this organizational directory only" - Single tenant
   - "Accounts in any organizational directory" - Multi-tenant
6. Click **"Register"**

### Step 2: Record Your Credentials

After registration, you'll see the app overview page.

**Copy these values:**
- **Application (client) ID** → Save as `AZURE_CLIENT_ID`
- **Directory (tenant) ID** → Save as `AZURE_TENANT_ID`

### Step 3: Create Client Secret

1. Go to **"Certificates & secrets"**
2. Click **"New client secret"**
3. **Description:** `Learning Lab Secret`
4. **Expires:** Choose "24 months" or your preference
5. Click **"Add"**
6. **Copy the secret value immediately** → Save as `AZURE_CLIENT_SECRET`
   - ⚠️ You cannot see this value again after leaving the page!

### Step 4: Configure Redirect URIs

1. Go to **"Authentication"**
2. Under **"Redirect URIs"**, click **"Add URI"**
3. Add these URIs:

```
http://localhost:8000/callback
https://<your-app-name>.azurewebsites.net/callback
```

Replace `<your-app-name>` with your actual Azure App Service name (you'll create this later).

4. Check **"Access tokens"** and **"ID tokens"** under "Implicit grant and hybrid flows"
5. Click **"Save"**

### Step 5: Configure API Permissions

1. Go to **"API permissions"**
2. Click **"Add a permission"**
3. Select **"Microsoft Graph"**
4. Click **"Delegated permissions"**
5. Search and select:
   - `openid`
   - `profile`
   - `email`
   - `offline_access`
6. Click **"Add permissions"**
7. Click **"Grant admin consent for [Your Org]"** (if you have admin rights)

---

## Local Development Setup

### Step 1: Clone the Repository

```bash
cd c:\Scripts\OAuth_Lab
```

### Step 2: Install Dependencies

```powershell
# Create virtual environment
python -m venv venv

# Activate virtual environment
venv\Scripts\Activate.ps1

# Install packages
pip install -r requirements.txt
```

### Step 3: Create .env File (Optional for Local Development)

Create a file named `.env` in the project root:

```env
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret
REDIRECT_URI=http://localhost:8000/callback
SECRET_KEY=your-secret-key-change-this
```

### Step 4: Run Locally

```powershell
python app.py
```

Open browser: **http://localhost:8000**

You should see the OAuth Lab home page with three flow options.

---

## Environment Variables

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `AZURE_TENANT_ID` | Yes | Your directory ID | `12345678-1234-1234-1234-123456789012` |
| `AZURE_CLIENT_ID` | Yes | Application ID | `87654321-4321-4321-4321-210987654321` |
| `AZURE_CLIENT_SECRET` | No* | Client secret | `abcd1234~xyz_ABC` |
| `REDIRECT_URI` | Yes | Callback URL | `http://localhost:8000/callback` |
| `SECRET_KEY` | No | Flask session key | `my-random-secret` |

\* Required for PKCE and Client Credentials flows. Not needed for Device Code flow.

---

## Testing Each Flow

### 1. Authorization Code Flow (PKCE)

**Best for:** Web applications

**Steps:**
1. Click **"Start PKCE Flow"**
2. You'll be redirected to Microsoft login
3. Sign in with your Azure AD account
4. Grant permissions to the app
5. You'll be redirected back with tokens displayed

**What you'll see:**
- Raw token response (JSON)
- Decoded ID Token (user information: name, email, etc.)
- Decoded Access Token (permissions and scopes)

**Key points:**
- Uses PKCE (Proof Key for Code Exchange) - most secure for web apps
- No client secret needed in URL (secret stays on server)
- Includes ID token (user info) and access token (API permissions)

---

### 2. Client Credentials Flow

**Best for:** Server-to-server, no user involved

**Requirements:**
- `AZURE_CLIENT_SECRET` must be set
- App must have "Application permissions" (not delegated)

**Steps:**
1. Click **"Start Client Credentials Flow"**
2. App immediately requests token from Azure AD
3. No user login required
4. Tokens displayed

**What you'll see:**
- Raw token response (JSON)
- Decoded Access Token only (no ID token)
- No user information

**Key points:**
- Used by background services, daemons, scheduled tasks
- Requires client secret
- No user interaction
- Access token only (no ID token)

---

### 3. Device Code Flow

**Best for:** Devices without browsers (CLI, IoT, smart devices)

**Steps:**
1. Click **"Start Device Code Flow"**
2. See a message like: "Visit https://microsoft.com/devicelogin and enter code: ABC123"
3. Open that URL **on a different device/browser** (or browser tab)
4. Enter the code
5. Sign in
6. App will poll and detect completion
7. Tokens displayed

**What you'll see:**
- Device code information
- Polling status
- Tokens once user completes on other device

**Key points:**
- Great for CLI tools and IoT devices
- User authenticates on another device
- App polls for completion
- No shared secret needed (optional)

---

## Deploying to Azure App Service

### Step 1: Create Azure App Service

```powershell
# Login to Azure
az login

# Create resource group
az group create --name oauth-lab-rg --location eastus

# Create App Service plan
az appservice plan create --name oauth-lab-plan --resource-group oauth-lab-rg --sku B1 --is-linux

# Create web app
az webapp create --resource-group oauth-lab-rg --plan oauth-lab-plan --name oauth-lab-app --runtime "PYTHON|3.11"
```

Replace `oauth-lab-app` with a globally unique name.

### Step 2: Set Environment Variables

```powershell
$resourceGroup = "oauth-lab-rg"
$appName = "oauth-lab-app"

az webapp config appsettings set `
  --resource-group $resourceGroup `
  --name $appName `
  --settings `
    AZURE_TENANT_ID="your-tenant-id" `
    AZURE_CLIENT_ID="your-client-id" `
    AZURE_CLIENT_SECRET="your-client-secret" `
    REDIRECT_URI="https://oauth-lab-app.azurewebsites.net/callback" `
    SECRET_KEY="your-random-secret-key" `
    SCM_DO_BUILD_DURING_DEPLOYMENT="true"
```

### Step 3: Deploy Code

```powershell
# From project directory
az webapp deployment source config-zip `
  --resource-group oauth-lab-rg `
  --name oauth-lab-app `
  --src <(Get-Content -Path "./app.zip" -AsByteStream | New-Object System.IO.MemoryStream)
```

Or use Git deployment:

```powershell
az webapp deployment source config-local-git `
  --resource-group oauth-lab-rg `
  --name oauth-lab-app

git remote add azure https://oauth-lab-app.scm.azurewebsites.net:443/oauth-lab-app.git
git push azure main
```

### Step 4: Update Azure AD Redirect URI

1. Go to Azure Portal → Microsoft Entra ID → App registrations → Your app
2. Go to **"Authentication"**
3. Add redirect URI: `https://oauth-lab-app.azurewebsites.net/callback`

### Step 5: Access Your App

Open: **https://oauth-lab-app.azurewebsites.net**

---

## Troubleshooting

### Issue: "Missing required environment variables"

**Cause:** `AZURE_CLIENT_ID` or `REDIRECT_URI` not set

**Fix:**
```powershell
# Check environment variables
echo $env:AZURE_CLIENT_ID
echo $env:REDIRECT_URI

# Set them
$env:AZURE_CLIENT_ID = "your-client-id"
$env:REDIRECT_URI = "http://localhost:8000/callback"
```

---

### Issue: "Invalid redirect URI"

**Cause:** Redirect URI not configured in Azure AD

**Fix:**
1. Go to Azure AD → App registrations → Your app → Authentication
2. Add the exact URI you're using (with trailing slash if needed)
3. Check spelling carefully

---

### Issue: "Invalid state parameter"

**Cause:** Browser cookies/session lost or CSRF attempt

**Fix:**
- Clear browser cookies
- Use incognito window
- Restart Flask app

---

### Issue: Device Code Flow won't start

**Cause:** Endpoint error

**Fix:**
- Check internet connection
- Verify `AZURE_CLIENT_ID` is correct
- Check app registration exists

---

### Issue: CORS errors

**Cause:** Browser blocking cross-origin requests

**Fix:**
- Ensure redirect URI is on same domain
- For local dev: use `http://localhost:8000` exactly
- For production: use HTTPS URL matching Azure AD configuration

---

### Issue: "Token request failed: 403"

**Cause:** Invalid credentials or permissions

**Fix:**
- Check `AZURE_CLIENT_SECRET` is correct
- Verify app has required permissions
- Check app isn't deleted from Azure AD

---

## Code Structure Explanation

### Helper Functions

**`decode_jwt(token)`**
- Decodes JWT without signature verification (learning only)
- Extracts and displays token claims
- In production, always verify signature!

**`generate_auth_url(flow_type, scope)`**
- Builds authorization URL with proper parameters
- Generates PKCE code challenge
- Creates random state for CSRF protection

**`format_json(data)`**
- Pretty prints JSON for display

### Routes

| Route | Purpose |
|-------|---------|
| `/` | Home page with flow options |
| `/pkce/start` | Initiate PKCE flow |
| `/callback` | Receive authorization code, exchange for tokens |
| `/clientcreds/start` | Start client credentials flow |
| `/device/start` | Request device code |
| `/device/poll` | Poll for device code completion |

---

## Security Notes

⚠️ **This is for learning purposes. Before production:**

1. **Always verify JWT signatures** - Use PyJWT library
2. **Use HTTPS only** - Never send tokens over HTTP
3. **Rotate secrets regularly** - Change `AZURE_CLIENT_SECRET` periodically
4. **Don't log tokens** - Never print tokens to logs
5. **Use secure session storage** - Don't use hardcoded secrets
6. **Validate scopes** - Only request needed permissions
7. **Implement token refresh** - Handle token expiration
8. **Add rate limiting** - Prevent brute force attacks

---

## Next Steps

- Explore different scopes in app registration
- Test with Graph API after getting access token
- Implement token refresh logic
- Add database to store user sessions
- Deploy to production with proper security

---

## Resources

- [Microsoft Identity Platform Documentation](https://learn.microsoft.com/en-us/entra/identity-platform/)
- [OAuth 2.0 Specification](https://tools.ietf.org/html/rfc6749)
- [PKCE RFC](https://tools.ietf.org/html/rfc7636)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [Azure App Service Documentation](https://learn.microsoft.com/en-us/azure/app-service/)

---

## Support

For issues:
1. Check the Troubleshooting section above
2. Review Flask and Azure AD documentation
3. Check browser console for errors (F12)
4. Check application logs: `az webapp log tail --resource-group oauth-lab-rg --name oauth-lab-app`

---

Happy learning! 🔐
