# SSOReady: Overview

**SSOReady** is a developer-friendly platform to add Single Sign-On (SSO) to your app. It supports modern identity standards like SAML and SCIM, and connects your app to multiple enterprise identity providers (IdPs) such as Okta, Azure AD, and Google Workspace.

## Key Concepts

- **SAML (Security Assertion Markup Language):**
  A standard protocol for SSO. Users authenticate with their organization's IdP and access your app without new credentials.

- **IdP (Identity Provider):**
  The external system (e.g., Okta, Azure AD) that authenticates users and provides identity info to your app via SSOReady.

- **SCIM (System for Cross-domain Identity Management):**
  A standard for automating user identity info exchange between IdPs and your app. SCIM enables automatic user and group provisioning/deprovisioning.

## AuthN and AuthZ Flow

- **Authentication (AuthN):**
  The process where a user proves their identity (e.g., via SAML SSO login). SSOReady handles the SAML handshake and provides authenticated user info to your app.

- **Authorization (AuthZ):**
  After authentication, your app decides what the user can access (roles, permissions). SSOReady provides identity and group info; your app enforces access control.

## Multiple IdPs & Organizations

- SSOReady lets you connect multiple organizations, each with their own IdP.
- Your app can dynamically select the correct IdP based on the user's email domain or other logic.

## Implementation Details

### SSOReady Client Initialization

```python
# Initialize SSOReady client with API key
sso_client = SSOReady(
    api_key=os.getenv("SSOREADY_API_KEY")
)
```

### Organization Configuration

Organizations are configured in `Config.ORGANIZATIONS`:

```python
ORGANIZATIONS = {
    "example.com": {
        "name": "Example Organization",
        "description": "Admin organization",
        "is_admin": True,
        "organization_id": "org_cd48zxghyarm0zr3sp349p59r"
    }
}
```

### SAML Authentication Flow

1. User enters email on login page
2. App extracts domain and gets organization config
3. App gets SAML redirect URL:
   ```python
   response = client.saml.get_saml_redirect_url(
       organization_id=org_config['organization_id'],
       organization_external_id=domain
   )
   ```
4. User is redirected to IdP
5. After authentication, IdP redirects back with SAML access code
6. App redeems code for user info:
   ```python
   response = client.saml.redeem_saml_access_code(
       saml_access_code=saml_access_code
   )
   ```

### Best Practices

1. Always use `get_sso_client()` helper to get the SSO client from app context
2. Configure callback URLs in SSOReady dashboard for each organization
3. Use organization_external_id (domain) to identify organizations
4. Handle SSO client initialization errors gracefully
5. Validate user info from SSOReady response

---

# SSOReady and Permit.io Integration: Technical Overview

## Multi-Tenant Architecture

- **Tenant Mapping**: Email domains are mapped to tenants in `Config.ORGANIZATIONS`
- Each organization has its own configuration including:
  - Organization ID
  - Admin status
  - Name and description

## Authentication Flow

1. **SSOReady** handles SAML-based authentication
2. The app determines the tenant based on the user's email domain
3. Organization ID is retrieved from Config.ORGANIZATIONS

## Authorization Flow

1. After authentication, the app syncs the user with **Permit.io**
2. Roles and permissions are assigned dynamically based on the tenant
3. Admin organizations get additional admin role

## Key Components

- **SSOReady**:
  - Handles SAML authentication
  - Connects to multiple IdPs based on email domain
- **Permit.io**:
  - Manages roles and permissions
  - Enforces fine-grained access control

## Best Practices

- Always validate the organization configuration for new email domains
- Use environment variables to securely store API keys
- Regularly update roles and permissions in Permit.io
- Handle SSO client initialization and errors gracefully
- Use app context for SSO client access

**In short:**
SSOReady simplifies SSO integration, supports SAML for authentication, SCIM for user provisioning, and lets you connect multiple IdPs for different organizations. Your app handles authorization using the identity data provided. The integration with Permit.io allows for dynamic role and permission management based on tenant mapping.
