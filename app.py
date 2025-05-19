from flask import Flask, redirect, request, session, render_template, url_for, jsonify
import os
from ssoready.client import SSOReady
import logging
from datetime import datetime, timedelta
from flask_jwt_extended import (
    JWTManager, create_access_token, get_jwt_identity,
    jwt_required, set_access_cookies, unset_jwt_cookies,
    get_jwt, verify_jwt_in_request
)
from functools import wraps
from permit import Permit
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Required environment variables
REQUIRED_ENV_VARS = [
    "SECRET_KEY",
    "JWT_SECRET_KEY",
    "SSOREADY_API_KEY",
    "SSOREADY_ORGANIZATION_ID",
    "PERMIT_SDK_TOKEN",
    "PERMIT_PDP_URL",
    "PERMIT_API_URL"
]

# Validate required environment variables
missing_vars = [var for var in REQUIRED_ENV_VARS if not os.getenv(var)]
if missing_vars:
    raise RuntimeError(f"Missing required environment variables: {', '.join(missing_vars)}")

# Set up logging
logging.basicConfig(level=logging.INFO)

# Initialize Permit.io client with environment variables
permit = Permit(
    token=os.getenv("PERMIT_SDK_TOKEN"),
    pdp=os.getenv("PERMIT_PDP_URL"),
    api_url=os.getenv("PERMIT_API_URL")
)

# Define your resources in Permit.io
RESOURCE_TYPES = {
    "tenant": ["read", "write", "delete"],
    "resource": ["read", "write", "delete"],
    "admin": ["access"]
}

def init_permit():
    """Initialize Permit.io resources and roles"""
    try:
        # Create resource types
        for resource, actions in RESOURCE_TYPES.items():
            permit.api.create_resource(
                resource,
                name=resource.title(),
                description=f"A {resource} resource",
                actions=actions
            )
            
        # Create roles
        permit.api.create_role(
            "user",
            name="User",
            description="Regular user role",
            permissions=[
                {"resource": "resource", "action": "read"},
                {"resource": "tenant", "action": "read"}
            ]
        )
        
        permit.api.create_role(
            "admin",
            name="Admin",
            description="Administrator role",
            permissions=[
                {"resource": "resource", "action": "*"},
                {"resource": "tenant", "action": "*"},
                {"resource": "admin", "action": "access"}
            ]
        )
    except Exception as e:
        app.logger.warning(f"Permit.io initialization error (may already exist): {str(e)}")

# Helper functions for authorization
def get_tenant_id(email):
    """Extract tenant ID from email domain"""
    return email.split('@')[1]

def permit_authorize(resource, action):
    """Decorator to check Permit.io authorization"""
    def wrapper(fn):
        @wraps(fn)
        def decorated(*args, **kwargs):
            try:
                verify_jwt_in_request()
                claims = get_jwt()
                user_email = claims.get('sub')
                user_tenant = claims.get('tenant_id')
                
                # For tenant-specific resources, ensure tenant_id in URL matches context
                if 'tenant_id' in kwargs and resource != 'admin':
                    requested_tenant = kwargs['tenant_id']
                    if not 'admin' in claims.get('roles', []) and requested_tenant != user_tenant:
                        app.logger.warning(
                            f"Cross-tenant access attempt: {user_email} ({user_tenant}) -> {requested_tenant}"
                        )
                        return jsonify({
                            "msg": "Cross-tenant access denied",
                            "error": "tenant_mismatch"
                        }), 403
                
                user = {
                    "key": user_email,
                    "first_name": claims.get('name'),
                    "email": user_email,
                    "tenant": user_tenant,
                    "roles": claims.get('roles', [])
                }
                
                # Context includes the specific tenant being accessed
                context = {
                    "tenant": kwargs.get('tenant_id', user_tenant),
                    "environment": os.getenv("FLASK_ENV", "development"),
                    "resource_type": resource
                }
                
                # Check permission using Permit.io
                permitted = permit.check(
                    user,
                    action,
                    resource,
                    context
                )
                
                if not permitted:
                    app.logger.warning(
                        f"Permission denied: {user_email} attempting {action} on {resource}"
                    )
                    return jsonify({
                        "msg": "Permission denied",
                        "error": "insufficient_permissions"
                    }), 403
                    
                return fn(*args, **kwargs)
                
            except Exception as e:
                app.logger.error(f"Authorization error: {str(e)}")
                return jsonify({
                    "msg": "Authorization failed",
                    "error": "auth_error"
                }), 500
                
        return decorated
    return wrapper

def requires_tenant_access(f):
    """Decorator to check if user has access to the tenant using Permit.io"""
    @wraps(f)
    def decorated(*args, **kwargs):
        verify_jwt_in_request()
        claims = get_jwt()
        requested_tenant_id = kwargs.get('tenant_id')
        user_tenant_id = claims.get('tenant_id')
        user_roles = claims.get('roles', [])
        user_email = claims.get('sub')
        
        # Admin can access all tenants
        if 'admin' in user_roles:
            app.logger.info(f"Admin user {user_email} accessing tenant {requested_tenant_id}")
            return f(*args, **kwargs)
            
        # Regular users can only access their own tenant
        if user_tenant_id != requested_tenant_id:
            app.logger.warning(
                f"Access denied: User from tenant {user_tenant_id} attempted to access tenant {requested_tenant_id}"
            )
            return jsonify({
                "msg": "Access denied: You can only access your own tenant",
                "error": "tenant_mismatch"
            }), 403
            
        # Additional Permit.io check for specific permissions
        user = {
            "key": user_email,
            "first_name": claims.get('name'),
            "email": user_email,
            "tenant": user_tenant_id,
            "roles": user_roles
        }
        
        context = {
            "tenant": requested_tenant_id,
            "environment": os.getenv("FLASK_ENV", "development")
        }
        
        try:
            # Check tenant access permission
            permitted = permit.check(
                user,
                "read",
                f"tenant:{requested_tenant_id}",
                context
            )
            
            if not permitted:
                app.logger.warning(
                    f"Permit.io denied access for user {user_email} to tenant {requested_tenant_id}"
                )
                return jsonify({
                    "msg": "Permission denied",
                    "error": "insufficient_permissions"
                }), 403
                
            return f(*args, **kwargs)
        except Exception as e:
            app.logger.error(f"Permit.io check failed: {str(e)}")
            return jsonify({
                "msg": "Authorization service error",
                "error": "auth_service_error"
            }), 500
            
    return decorated

# Helper function to verify SSO response
def verify_sso_response(response):
    """Verify the SSO response and return user info."""
    if not response or not hasattr(response, 'email'):
        raise ValueError("Invalid SSO response: missing email")
    
    user_info = {
        'email': response.email,
        'name': response.email.split('@')[0],
        'picture': None,
        'authenticated': True,
        'timestamp': datetime.now().isoformat()
    }
    
    return user_info

# Initialize SSOReady client with API key from environment
sso_client = SSOReady(
    api_key=os.getenv("SSOREADY_API_KEY"),
)

app = Flask(__name__)

# Configure Flask app from environment variables
app.secret_key = os.getenv("SECRET_KEY")
app.config.update(
    JWT_SECRET_KEY=os.getenv("JWT_SECRET_KEY"),
    JWT_ACCESS_TOKEN_EXPIRES=int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES", 3600))
)

# Initialize JWT
jwt = JWTManager(app)

@app.route('/')
def index():
    """Home page route."""
    user_info = session.get('user_info')
    return render_template('index.html', user_info=user_info)

@app.route('/login')
def login():
    """Initiate the SSO login process."""
    try:
        # Get the email from the form
        email = request.args.get('email')
        if not email:
            return jsonify({
                'error': 'Email address not provided',
                'status': 'error'
            }), 400
        
        # Extract the domain from the email address
        domain = email.split('@')[-1]
        if not domain:
            return jsonify({
                'error': 'Invalid email format',
                'status': 'error'
            }), 400
        
        # Get the SAML redirect URL
        try:
            redirect_url = sso_client.saml.get_saml_redirect_url(
                organization_external_id=domain,
                organization_id=os.getenv("SSOREADY_ORGANIZATION_ID")
            ).redirect_url
            
            if not redirect_url:
                raise ValueError("Invalid redirect URL received")
            
            return redirect(redirect_url)
            
        except Exception as e:
            app.logger.error(f"Error getting SAML redirect URL: {str(e)}")
            raise
            
    except Exception as e:
        app.logger.error(f"Error initiating SSO login: {str(e)}")
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

@app.route('/callback')
def callback():
    """Handle the SSO callback. Only trust user info from a real SSOReady SAML response."""
    try:
        saml_access_code = request.args.get('saml_access_code')
        if not saml_access_code:
            return jsonify({'error': 'SAML access code not received', 'status': 'error'}), 400
        # Redeem the SAML access code for user information (validated by SSOReady)
        response = sso_client.saml.redeem_saml_access_code(saml_access_code=saml_access_code)
        if not response:
            raise ValueError("Invalid SSO response")
        # Log the full SSOReady response for debugging
        app.logger.info(f"Full SSOReady response: {response.__dict__ if hasattr(response, '__dict__') else str(response)}")
        # Only trust user info from SSOReady response
        user_info = verify_sso_response(response)
        
        # Create JWT token with tenant and role information
        tenant_id = get_tenant_id(user_info['email'])
        # For demo purposes, assign roles based on email
        roles = ['user']
        if user_info['email'].startswith('admin'):
            roles.append('admin')
            
        # Sync user with Permit.io
        try:
            # Sync tenant if it doesn't exist
            permit.api.sync_tenant(
                tenant_id,
                name=f"Tenant {tenant_id}",
                description=f"Tenant for {tenant_id}"
            )
            
            # Sync user with Permit.io
            permit.api.sync_user(
                user_info['email'],
                name=user_info['name'],
                email=user_info['email'],
                roles=roles,
                tenant=tenant_id
            )
        except Exception as e:
            app.logger.error(f"Error syncing with Permit.io: {str(e)}")
            
        access_token = create_access_token(
            identity=user_info['email'],
            additional_claims={
                'tenant_id': tenant_id,
                'roles': roles,
                'name': user_info['name']
            }
        )
        
        # Store token in session
        session['user_info'] = user_info
        session['access_token'] = access_token
        
        app.logger.info(f"User {user_info['email']} successfully authenticated via SAML.")
        return redirect(url_for('home'))
    except Exception as e:
        app.logger.error(f"Error processing SSO callback: {str(e)}")
        return jsonify({'error': str(e), 'status': 'error'}), 500

@app.route('/logout')
def logout():
    """Log the user out."""
    session.clear()
    response = redirect(url_for('index'))
    unset_jwt_cookies(response)
    return response

@app.route('/api/saml-lookup', methods=['POST'])
def saml_lookup():
    """Lookup SAML organization for an email. Returns SAML redirect URL if SAML is enabled for the domain."""
    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    if not email or '@' not in email:
        return jsonify({'saml_url': None}), 200
    domain = email.split('@')[-1]
    # For demo: only domains ending with 'example.com' are SAML-enabled
    if domain.endswith('example.com'):
        try:
            redirect_url = sso_client.saml.get_saml_redirect_url(
                organization_external_id=domain,
                organization_id=os.getenv("SSOREADY_ORGANIZATION_ID")
            ).redirect_url
            return jsonify({'saml_url': redirect_url}), 200
        except Exception as e:
            app.logger.error(f"SAML lookup error: {str(e)}")
            return jsonify({'saml_url': None}), 200
    return jsonify({'saml_url': None}), 200

@app.route('/home')
def home():
    """Home page after login. Only accessible if logged in."""
    user_info = session.get('user_info')
    if not user_info:
        return redirect(url_for('index'))
    return render_template('home.html', user_info=user_info)

@app.route('/api/tenant/<tenant_id>/resources')
@jwt_required()
@requires_tenant_access
@permit_authorize("resource", "read")
def get_tenant_resources(tenant_id):
    """Get resources for a specific tenant. Requires tenant access."""
    try:
        claims = get_jwt()
        user_tenant = claims.get('tenant_id')
        user_email = claims.get('sub')
        
        # Log the access
        app.logger.info(f"User {user_email} accessing resources for tenant {tenant_id}")
        
        # In a real application, you would fetch this from a database
        # with proper tenant isolation
        resources = [
            {'id': 1, 'name': f'Resource 1 - {tenant_id}', 'type': 'document'},
            {'id': 2, 'name': f'Resource 2 - {tenant_id}', 'type': 'project'}
        ]
        
        return jsonify({
            'tenant_id': tenant_id,
            'user_tenant': user_tenant,
            'resources': resources,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        app.logger.error(f"Error fetching tenant resources: {str(e)}")
        return jsonify({
            "msg": "Error fetching resources",
            "error": "resource_fetch_error"
        }), 500

@app.route('/api/admin/tenants')
@jwt_required()
@permit_authorize("admin", "access")
def list_tenants():
    """List all tenants. Requires admin access."""
    return jsonify({
        'tenants': [
            {'id': 'company1.com', 'name': 'Company 1'},
            {'id': 'company2.com', 'name': 'Company 2'}
        ]
    })

@app.route('/api/me')
@jwt_required()
def get_user_info():
    """Get current user information from JWT"""
    claims = get_jwt()
    return jsonify({
        'email': get_jwt_identity(),
        'tenant_id': claims['tenant_id'],
        'roles': claims['roles'],
        'name': claims['name']
    })

if __name__ == '__main__':
    app.run(debug=True)
