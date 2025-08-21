# OIDC-Reflector  
CILogon OIDC Reflector

## Setup Instructions

### 1. Install Dependencies  
    pip install -r requirements.txt

### 2. Create `.env` File  
In the root directory, create a `.env` file with the following configuration:

#### Local Session Token  
    APP_SESSION_SECRET=<any random secret, only stored here>

#### OIDC Client Configuration  
You can store multiple client configurations in the `.env` file.  
Comment out any unused configuration and ensure only **one** is active.  

Example:  
```
# OIDC Client CONFIG (Template)
# CLIENT_ID=<Provided by the OIDC Client upon creation>
# CLIENT_SECRET=<Provided by the OIDC Client upon creation>
# REDIRECT_URI=<Callback URL configured in the OIDC client>
# TOKEN_ENDPOINT=https://<your client URL>/oauth2/token
# DISCOVERY_URL=https://<your client URL>/.well-known/openid-configuration

# Active OIDC Client CONFIG
CLIENT_ID=<Provided by the OIDC Client upon creation>
CLIENT_SECRET=<Provided by the OIDC Client upon creation>
REDIRECT_URI=<Callback URL configured in the OIDC client>
TOKEN_ENDPOINT=https://<your client URL>/oauth2/token
DISCOVERY_URL=https://<your client URL>/.well-known/openid-configuration
```

#### Standard App Configuration  
```
FLASK_APP=oidc_reflector
FLASK_RUN_PORT=5000
FLASK_RUN_HOST=0.0.0.0
```

### 3. Run the Application  
    python oidc-reflector.py

### 4. Access the App  
Open your browser and navigate to:  

    http://localhost:5000

### 5. Authenticate  
- Follow the login steps.  
- Authenticate with your OIDC provider.  
- The token details will be reflected back in the app.  

---

## Notes  
- Keep your `.env` file secure.  
- Never commit secrets (Client IDs, Secrets, Tokens) to version control.  
