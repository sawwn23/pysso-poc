from flask import Blueprint, jsonify, session, redirect, url_for, current_app, request, render_template, flash
from flask_jwt_extended import (
    create_access_token, set_access_cookies, unset_jwt_cookies,
    get_jwt_identity, jwt_required, get_jwt, verify_jwt_in_request
)
from functools import wraps
from datetime import datetime, timedelta
import logging
import os

# Import from app
from flask import current_app
from app.config.config import config as app_config
from app.utils.helpers import get_tenant_id, verify_sso_response
from app.auth.decorators import permit_authorize

# Get the permit instance from the app
permit = None

def get_sso_client():
    """Helper to get the SSO client from the current app context"""
    return current_app.extensions.get('sso_client') if current_app else None

# Set up logging
logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__)

def requires_roles(*roles):
    """Decorator to check if user has any of the required roles"""
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            verify_jwt_in_request()
            user_roles = get_jwt().get('roles', [])
            if not any(role in user_roles for role in roles):
                return jsonify({"error": "Insufficient permissions"}), 403
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Handle login and SSO redirection."""
    # If user is already authenticated, redirect to tenant home
    if 'user' in session:
        return redirect(f"/api/tenant/{session['user'].get('org_id', 'default')}")
    
    if request.method == 'POST':
        email = request.form.get('email')
        logger.info(f"Login attempt for email: {email}")
        
        if not email or '@' not in email:
            flash('Please enter a valid email address', 'error')
            return render_template('auth/login.html')
            
        try:
            domain = email.split('@')[-1].lower()
            
            # Get tenant info
            from app.config.tenant_mapping import get_tenant_info
            tenant_info = get_tenant_info(domain)
            if not tenant_info:
                flash('Invalid organization domain', 'error')
                return render_template('auth/login.html')
                
            # Store org context in session
            session['org_context'] = {
                'org_id': tenant_info['id'],
                'org_name': tenant_info['name'],
                'is_admin': tenant_info.get('is_admin', False)
            }
            
            # Get SSO client from app context
            sso_client = current_app.extensions.get('sso_client')
            if not sso_client:
                raise ValueError("SSO client not properly initialized")
                
            # Initialize SSO flow
            sso_org_id = current_app.config.get('SSOREADY_ORGANIZATION_ID') or os.getenv('SSOREADY_ORGANIZATION_ID')
            if not sso_org_id:
                raise ValueError("SSO organization ID not configured")
                
            # Get SAML redirect URL
            response = sso_client.saml.get_saml_redirect_url(
                organization_id=sso_org_id,
                organization_external_id=domain  # Use domain as external ID
            )
            
            if not response or not hasattr(response, 'redirect_url') or not response.redirect_url:
                raise ValueError("Failed to get SSO redirect URL")
            
            logger.info(f"Redirecting to SSO URL: {response.redirect_url}")
            return redirect(response.redirect_url)
            
        except Exception as sso_error:
            logger.error(f"SSO Error: {str(sso_error)}", exc_info=True)
            flash('SSO authentication failed. Please try again or contact support.', 'error')
            return redirect(url_for('auth.login'))
            
        except Exception as e:
            logger.error(f"Login error: {str(e)}", exc_info=True)
            flash('Authentication failed. Please try again.', 'error')
    
    # GET request - show login form
    return render_template('auth/login.html')
    
    # GET request - show login form
    return render_template('auth/login.html')

@auth_bp.route('/callback')
def callback():
    """Handle the SSO callback and set up user session."""
    try:
        saml_access_code = request.args.get('saml_access_code')
        if not saml_access_code:
            logger.error("No SAML access code in callback")
            flash('Authentication failed: No access code received', 'error')
            return redirect(url_for('auth.login'))
        
        # Get organization context from session
        org_context = session.get('org_context', {})
        if not org_context:
            logger.error("No organization context in session")
            flash('Session expired. Please login again.', 'error')
            return redirect(url_for('auth.login'))
        
        # Get SSO client and handle the access code
        sso_client = get_sso_client()
        if not sso_client:
            raise ValueError("SSO client not available")
            
        # Redeem the SAML access code
        response = sso_client.saml.redeem_saml_access_code(saml_access_code=saml_access_code)
        
        # Extract user info from response
        if not response or not hasattr(response, 'email'):
            raise ValueError("Invalid response from SSO provider")
            
        # Create user info
        email = response.email
        domain = email.split('@')[-1].lower()
        
        from app.config.tenant_mapping import get_tenant_info
        tenant_info = get_tenant_info(domain)
        
        # Double check tenant info matches session context
        if tenant_info['id'] != org_context['org_id']:
            logger.error(f"Tenant mismatch: {tenant_info['id']} != {org_context['org_id']}")
            flash('Authentication failed: Organization mismatch', 'error')
            return redirect(url_for('auth.login'))
            
        user_info = {
            'email': email,
            'name': email.split('@')[0],
            'org_id': tenant_info['id'],
            'org_name': tenant_info['name'],
            'roles': ['admin', 'user'] if tenant_info.get('is_admin', False) else ['user']
        }
        
        # Sync with Permit.io
        try:
            from app.core.extensions import permit
            if permit:
                # Create/update tenant in Permit.io
                permit.api.create_tenant(
                    key=user_info['org_id'],
                    name=user_info['org_name'],
                    description=f"Tenant for {user_info['org_name']}"
                )
                
                # Create/update user in Permit.io
                permit.api.create_user(
                    key=user_info['email'],
                    email=user_info['email'],
                    first_name=user_info['name']
                )
                
                # Assign roles to user
                for role in user_info['roles']:
                    permit.api.assign_role(
                        user=user_info['email'],
                        role=role,
                        tenant=user_info['org_id']
                    )
        except Exception as e:
            logger.error(f"Error syncing with Permit.io: {str(e)}")
            # Continue with login even if Permit sync fails
            
        # Create JWT token
        access_token = create_access_token(
            identity=user_info['email'],
            additional_claims={
                'org_id': user_info['org_id'],
                'roles': user_info['roles'],
                'name': user_info['name']
            }
        )
        
        # Store user in session
        session['user'] = user_info
        
        # Redirect to tenant home
        resp = redirect(f"/api/tenant/{user_info['org_id']}")
        set_access_cookies(resp, access_token)
        
        # Clean up
        session.pop('org_context', None)
        
        return resp
        
    except Exception as e:
        logger.error(f"Callback error: {str(e)}", exc_info=True)
        flash('Authentication failed. Please try again.', 'error')
        return redirect(url_for('auth.login'))
        if not response:
            raise ValueError("Invalid SSO response")
            
        current_app.logger.info(f"SAML Response: {response.__dict__ if hasattr(response, '__dict__') else str(response)}")
        user_info = verify_sso_response(response)
        
        tenant_id = get_tenant_id(user_info['email'])
        roles = ['user']
        if user_info['email'].startswith('admin'):
            roles.append('admin')
            
        try:
            from app.core.extensions import permit
            # Sync tenant and user with Permit.io
            permit.api.sync_tenant(
                tenant_id,
                name=f"Tenant {tenant_id}",
                description=f"Tenant for {tenant_id}"
            )
            
            permit.api.sync_user(
                user_info['email'],
                name=user_info['name'],
                email=user_info['email'],
                roles=roles,
                tenant=tenant_id
            )
        except Exception as e:
            current_app.logger.error(f"Error syncing with Permit.io: {str(e)}")
            
        access_token = create_access_token(
            identity=user_info['email'],
            additional_claims={
                'tenant_id': tenant_id,
                'roles': roles,
                'name': user_info['name']
            }
        )
        
        session['user_info'] = user_info
        response = redirect(url_for('tenant.home'))
        set_access_cookies(response, access_token)
        
        current_app.logger.info(f"User {user_info['email']} authenticated via SAML")
        return response
        
    except Exception as e:
        current_app.logger.error(f"Error in callback: {str(e)}")
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/logout')
def logout():
    """Log the user out and clear all session data."""
    try:
        # Create response
        resp = redirect(url_for('auth.login'))
        
        # Clear session data
        session.clear()
        
        # Clear JWT cookies
        unset_jwt_cookies(resp)
        
        # Clear session cookie
        resp.delete_cookie('session')
        
        # Add cache control headers
        resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        resp.headers['Pragma'] = 'no-cache'
        resp.headers['Expires'] = '0'
        
        flash('You have been successfully logged out.', 'info')
        return resp
        
    except Exception as e:
        logger.error(f"Logout error: {str(e)}", exc_info=True)
        flash('An error occurred during logout. Please try again.', 'error')
        return redirect(url_for('auth.login'))

@auth_bp.route('/me')
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
