# SSO-Ready Flask Application

A secure, multi-tenant Flask application with JWT authentication and role-based access control using SSOReady and Permit.io.

## Features

- 🔐 Secure JWT-based authentication
- 🏢 Multi-tenant architecture
- 👥 Role-based access control (RBAC)
- 🔄 SSO integration via SSOReady

## Prerequisites

- Python 3.8+
- pip (Python package manager)
- SSOReady account and API key

## Quick Start

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/python-ssoready-app.git
   cd python-ssoready-app
   ```

2. Create and activate a virtual environment:

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Copy the example environment file and update with your credentials:

   ```bash
   cp .env.example .env
   ```

   Edit the `.env` file with your actual credentials:
   ```env
   SECRET_KEY=your-secret-key
   JWT_SECRET_KEY=your-jwt-secret-key
   SSOREADY_API_KEY=your-ssoready-api-key
   ```

5. Configure organizations in `app/config/config.py`:
   ```python
   ORGANIZATIONS = {
       "example.com": {
           "name": "Example Organization",
           "description": "Admin organization",
           "is_admin": True,
           "organization_id": "your-org-id"
       }
   }
   ```

6. Run the application:

   ```bash
   python run.py
   ```

   The application will be available at `http://localhost:5000`

## Configuration

### Required Environment Variables

- `SECRET_KEY`: Flask secret key for session encryption
- `JWT_SECRET_KEY`: Secret key for JWT token signing
- `SSOREADY_API_KEY`: Your SSOReady API key

### Optional Environment Variables

- `FLASK_ENV`: Set to 'development' or 'production' (default: development)
- `PORT`: Port to run the application on (default: 5000)
- `LOG_LEVEL`: Logging level (default: INFO)

## Multi-Tenant Authorization System

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

### SSO Integration

- **SSOReady** handles SAML-based authentication
- The app uses the email domain to select the IdP
- Example:
  ```python
  response = client.saml.get_saml_redirect_url(
      organization_id=org_config['organization_id'],
      organization_external_id=domain
  )
  ```

### Best Practices

1. Always use `get_sso_client()` helper to get the SSO client
2. Configure callback URLs in SSOReady dashboard
3. Use organization_external_id (domain) to identify organizations
4. Handle SSO client initialization errors gracefully
5. Validate user info from SSOReady response

## API Endpoints

### Authentication
- `GET /login`: Login page
- `GET /callback`: SSO callback handler
- `GET /logout`: Logout handler
- `GET /api/me`: Get current user information

### Tenant Management
- `GET /api/tenant/<tenant_id>/home`: Tenant home page
- `GET /api/admin/tenants`: List all tenants (admin only)

## Security Considerations

- JWT tokens for API authentication
- Secure session management
- Role-based access control
- Tenant isolation
- SSO client initialization checks

## Error Handling

- SSO service unavailability
- Invalid SAML access codes
- Missing organization configuration
- Authentication failures
