# SSOReady Python Application Documentation

## Overview
This is a Flask-based web application that implements Single Sign-On (SSO) authentication using SSOReady. The application supports multi-tenant functionality where each tenant is identified by their email domain.

## Features
- SSO Authentication using SSOReady
- Multi-tenant support
- Role-based access control (Admin and User roles)
- JWT-based session management
- Flask-Login integration
- Secure cookie handling

## Project Structure
```
python-ssoready-app/
├── app/
│   ├── admin/             # Admin-specific routes and functionality
│   ├── auth/              # Authentication routes and logic
│   ├── config/            # Configuration files
│   ├── core/              # Core functionality and extensions
│   ├── models/            # Data models
│   ├── tenant/            # Tenant-specific routes and functionality
│   ├── templates/         # HTML templates
│   └── utils/             # Utility functions
├── .env                   # Environment variables
├── run.py                 # Application entry point
```

## Configuration
The application requires the following environment variables:
- `SSOREADY_API_KEY`: Your SSOReady API key
- `SECRET_KEY`: Flask secret key for session encryption
- `JWT_SECRET_KEY`: Secret key for JWT token signing

## Organization Configuration
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

## Authentication Flow
1. User visits `/login`
2. User enters their email
3. Application extracts domain and gets organization config
4. Application gets SAML redirect URL from SSOReady
5. User is redirected to their organization's IdP
6. After successful SSO authentication, user is redirected to `/callback`
7. Application redeems SAML access code for user info
8. Application creates/updates user record and sets up session
9. User is redirected to home page

## Role Management
- Users from organizations with `is_admin: true` get admin role
- All other users get the 'user' role

## API Endpoints

### Authentication
- `GET /login`: Login page
- `GET /callback`: SSO callback handler
- `GET /logout`: Logout handler
- `GET /api/me`: Get current user information

### Tenant Management
- `GET /api/tenant/<tenant_id>/home`: Tenant home page
- `GET /api/admin/tenants`: List all tenants (admin only)

## SSOReady Integration

### Client Initialization
```python
sso_client = SSOReady(
    api_key=os.getenv("SSOREADY_API_KEY")
)
```

### SAML Authentication
```python
# Get SAML redirect URL
response = client.saml.get_saml_redirect_url(
    organization_id=org_config['organization_id'],
    organization_external_id=domain
)

# Redeem SAML access code
response = client.saml.redeem_saml_access_code(
    saml_access_code=saml_access_code
)
```

### Best Practices
1. Always use `get_sso_client()` helper to get the SSO client
2. Configure callback URLs in SSOReady dashboard
3. Use organization_external_id (domain) to identify organizations
4. Handle SSO client initialization errors gracefully
5. Validate user info from SSOReady response

## Error Handling
- SSO service unavailability
- Invalid SAML access codes
- Missing organization configuration
- Authentication failures

## Security Considerations
- JWT tokens for API authentication
- Secure session management
- Role-based access control
- Tenant isolation
- SSO client initialization checks

## Session Management
The application uses a combination of:
- Flask-Login for user session management
- JWT tokens for API authentication
- Secure cookies for token storage

## Security Features
- JWT-based authentication
- Role-based access control
- Secure cookie handling
- Session cleanup on logout
- Tenant isolation

## Logging
The application uses Python's logging module with:
- DEBUG level in development
- INFO level in production
- File-based logging in production
- Console logging in development

## Dependencies
- Flask
- Flask-JWT-Extended
- Flask-Login
- SSOReady Python SDK
- Python-dotenv

## Getting Started
1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Set up environment variables in `.env`
4. Run the application: `python run.py`

## Development
- Debug mode is enabled by default
- Logging is set to DEBUG level
- Hot reloading is enabled

## Production Deployment
- Set `FLASK_ENV=production`
- Configure proper logging
- Use secure cookie settings
- Set up proper SSL/TLS
- Configure proper session storage

## Best Practices
- Always use HTTPS in production
- Regularly rotate secrets
- Monitor application logs
- Keep dependencies updated
- Follow security best practices

## Troubleshooting
Common issues and solutions:
1. SSO Authentication Failures
   - Check SSOReady configuration
   - Verify organization ID
   - Check API key validity

2. Session Issues
   - Clear browser cookies
   - Check JWT token expiration
   - Verify session configuration

3. Permission Issues
   - Verify user roles
   - Check tenant access
   - Verify JWT claims
