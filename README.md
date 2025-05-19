# SSO-Ready Flask Application

A secure, multi-tenant Flask application with JWT authentication and role-based access control using SSOReady and Permit.io.

## Features

- 🔐 Secure JWT-based authentication
- 🏢 Multi-tenant architecture
- 👥 Role-based access control (RBAC)
- 🔄 SSO integration via SSOReady
- 🔒 Fine-grained permissions with Permit.io
- 🚀 Production-ready configuration

## Prerequisites

- Python 3.8+
- pip (Python package manager)
- SSOReady account and API key
- Permit.io account and SDK token

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
   
   Edit the `.env` file with your actual credentials.

5. Run the application:
   ```bash
   python run.py
   ```

   The application will be available at `http://localhost:5000`

## Configuration

### Required Environment Variables

- `SECRET_KEY`: Flask secret key for session encryption
- `JWT_SECRET_KEY`: Secret key for JWT token signing
- `JWT_ACCESS_TOKEN_EXPIRES`: Token expiration time in seconds (default: 3600)
- `SSOREADY_API_KEY`: Your SSOReady API key
- `SSOREADY_ORGANIZATION_ID`: Your SSOReady organization ID
- `PERMIT_SDK_TOKEN`: Your Permit.io SDK token
- `PERMIT_PDP_URL`: Permit PDP URL (default: http://localhost:7766)
- `PERMIT_API_URL`: Permit API URL (default: https://api.permit.io)

### Optional Environment Variables

- `FLASK_ENV`: Set to 'development' or 'production' (default: development)
- `PORT`: Port to run the application on (default: 5000)
- `LOG_LEVEL`: Logging level (default: INFO)

## Multi-tenant Authorization System

This application implements a multi-tenant authorization system with the following features:

### Tenant Isolation

- Each user belongs to a tenant (organization) based on their email domain
- Resources are isolated by tenant
- Users can only access their own tenant's resources

### Role-Based Access Control (RBAC)

- Basic roles: 'user', 'admin'
- Admins have access to all tenants
- Role-based API endpoints

### JWT-Based Authentication

- Secure JWT tokens issued after successful SSO
- Tokens include tenant and role information
- Token-based API access

### Protected API Endpoints

- `/api/me` - Get current user information
- `/api/tenant/<tenant_id>/resources` - Access tenant-specific resources
- `/api/admin/tenants` - List all tenants (admin only)

### Demo Users

- Regular User: user@example.com
- Admin User: admin@example.com
- Tenant 1: user@company1.com
- Tenant 2: user@company2.com

3. Run in development:
   ```bash
   flask run
   ```
   App will be at http://localhost:5000

## Self-hosted SSOReady

You can run SSOReady yourself using docker-compose:

```bash
docker-compose up -d
```

DB migration to setup ssoready db schema

```bash
docker run --network=host ssoready/ssoready-migrate:sha-18090f8 -d 'postgres://postgres:password@localhost/postgres?sslmode=disable' up
```

cp env.example .env

Fill in the .env file with your own values.

## Multiple IdPs / Multiple Orgs

- SSOReady supports multiple organizations (IdPs) via the `organization_external_id` parameter.
- The app uses the email domain to select the IdP:
  - When a user logs in, the domain part of their email determines which organization/IdP to use.
  - You can map domains to organization IDs in your code or config.
- Example (in `app.py`):
  ```python
  domain = email.split('@')[-1]
  sso_client.saml.get_saml_redirect_url(
      organization_external_id=domain,  # or your mapping
      organization_id=os.getenv("SSOREADY_ORGANIZATION_ID")
  )
  ```
- Register each domain/IdP in your SSOReady dashboard.

The services will be available at:

Authentication: http://localhost:8080
API: http://localhost:8081
App: http://localhost:8082
Admin: http://localhost:8083
Flask: http://localhost:5000

## Notes

- Only trust user info returned from the SSOReady callback.
- For real SAML/SSO, use production credentials and real IdPs.

## Usage

1. Click the "Login with SSO" button on the homepage to initiate the SAML authentication flow.
2. You'll be redirected to your identity provider's login page.
3. After successful authentication, you'll be redirected back to the application with your user information displayed.
4. Click the "Logout" button to end your session.

## Configuration

### Environment Variables

- `SECRET_KEY`: A secret key for Flask session encryption
- `SSOREADY_API_KEY`: Your SSOReady API key
- `SSOREADY_ORGANIZATION_ID`: Your organization ID in SSOReady
- `FLASK_ENV`: Set to 'development' for development, 'production' for production
- `FLASK_APP`: Entry point of the Flask application

## Authorization with Permit.io

The application uses [Permit.io](https://permit.io) for fine-grained authorization control:

### Resource Types

- `tenant`: Represents organization resources with read/write/delete permissions
- `resource`: Represents tenant-specific resources with read/write/delete permissions
- `admin`: Special resource type for administrative access

### Roles and Permissions

1. User Role:

   - Can read tenant resources
   - Can read their own tenant information

2. Admin Role:
   - Full access to all resources
   - Can manage tenants
   - Access to admin features

### Permit.io Configuration

Configure the following environment variables:

```env
PERMIT_SDK_TOKEN=your-permit-token
PERMIT_PDP_URL=https://cloudpdp.api.permit.io
PERMIT_API_URL=https://api.permit.io
```

### How It Works

1. Users are authenticated via SSO
2. User data is synced with Permit.io
3. Permit.io enforces authorization rules based on:
   - User's role
   - User's tenant
   - Resource type
   - Action type

### Protected Endpoints

- `/api/tenant/<tenant_id>/resources`: Protected by tenant access and resource read permission
- `/api/admin/tenants`: Protected by admin access permission
- `/api/me`: Protected by JWT authentication
