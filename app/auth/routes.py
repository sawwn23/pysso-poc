from flask import Blueprint, jsonify, session, redirect, url_for, current_app, request, render_template, flash
from flask_jwt_extended import (
    create_access_token, set_access_cookies, unset_jwt_cookies,
    get_jwt_identity, jwt_required, get_jwt, verify_jwt_in_request
)
from functools import wraps
from datetime import datetime, timedelta
import logging
import os
import asyncio
from flask_login import login_user, logout_user, login_required, current_user
from app.core.extensions import sso_client
from app.models.user import User
from app.core.extensions import run_sync
from app.config.config import Config

# Import from app
from flask import current_app
from app.config.config import config as app_config, Config
from app.utils.helpers import get_tenant_id, verify_sso_response

# Set up logging
logger = logging.getLogger(__name__)

# In-memory user storage
_users = {}

def get_sso_client():
    """Helper to get the SSO client from the current app context"""
    return current_app.extensions.get('sso_client') if current_app else None

def run_sync(coro):
    """Run an async coroutine synchronously"""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)

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
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            flash('Email is required', 'error')
            return render_template('auth/login.html')
            
        try:
            # Get tenant domain from email
            domain = email.split('@')[1]
            
            # Get organization config
            org_config = Config.get_organization(domain)
            if not org_config:
                flash('Your organization is not configured for SSO', 'error')
                return render_template('auth/login.html')
                
            # Get SSO client
            client = get_sso_client()
            if not client:
                flash('SSO service is not available', 'error')
                return render_template('auth/login.html')
                
            # Get SSO URL
            response = client.saml.get_saml_redirect_url(
                organization_id=org_config['organization_id'],
                organization_external_id=domain
            )
            
            return redirect(response.redirect_url)
            
        except Exception as e:
            current_app.logger.error(f"Error during login: {str(e)}", exc_info=True)
            flash('An error occurred during login', 'error')
            return render_template('auth/login.html')
            
    return render_template('auth/login.html')

@auth_bp.route('/callback')
def callback():
    """Handle the SSO callback and set up user session."""
    try:
        # Get the SAML access code from the request
        saml_access_code = request.args.get('saml_access_code')
        if not saml_access_code:
            flash('No SAML access code provided', 'error')
            return redirect(url_for('auth.login'))
            
        # Get SSO client
        client = get_sso_client()
        if not client:
            flash('SSO service is not available', 'error')
            return redirect(url_for('auth.login'))
            
        # Redeem the SAML access code
        response = client.saml.redeem_saml_access_code(saml_access_code=saml_access_code)
        if not response:
            flash('Invalid SAML access code', 'error')
            return redirect(url_for('auth.login'))
            
        # Get user info from the response
        email = response.email
        domain = email.split('@')[1]
        
        # Get organization config from Config
        org_config = Config.get_organization(domain)
        if not org_config:
            flash('Your organization is not configured for SSO', 'error')
            return redirect(url_for('auth.login'))
            
        user_info = {
            'email': email,
            'name': response.name if hasattr(response, 'name') else email.split('@')[0],
            'tenant_id': domain,
            'org_id': org_config['organization_id']
        }
        
        # Get or create user
        user = User.get_by_email(user_info['email'])
        if not user:
            user = User.create(
                email=user_info['email'],
                name=user_info['name'],
                tenant_id=user_info['tenant_id']
            )
            
        # Determine user roles based on domain
        roles = ['user']
        if org_config.get('is_admin', False):
            roles.append('admin')
            
        # Log in the user with Flask-Login
        login_user(user)
            
        # Create JWT token
        access_token = create_access_token(
            identity=user.id,
            additional_claims={
                'email': user.email,
                'tenant_id': user.tenant_id,
                'org_id': user_info['org_id'],
                'roles': roles,
                'name': user.name
            }
        )
        
        # Create response with both Flask-Login session and JWT cookie
        resp = redirect(url_for('main.home'))
        set_access_cookies(resp, access_token)
        
        # Set session data
        session['user_id'] = user.id
        session['tenant_id'] = user.tenant_id
        session['org_id'] = user_info['org_id']
        session['roles'] = roles
        
        return resp
        
    except Exception as e:
        current_app.logger.error(f"Error in callback: {str(e)}", exc_info=True)
        flash('Error during authentication', 'error')
        return redirect(url_for('auth.login'))

@auth_bp.route('/logout')
@login_required
def logout():
    """Log the user out and clear all session data."""
    resp = redirect(url_for('auth.login'))
    unset_jwt_cookies(resp)
    logout_user()
    session.clear()
    return resp

@auth_bp.route('/api/me')
@jwt_required()
def get_user_info():
    """Get current user information from JWT"""
    try:
        claims = get_jwt()
        return jsonify({
            'email': claims.get('email'),
            'tenant_id': claims.get('tenant_id'),
            'roles': claims.get('roles', ['user']),
            'name': claims.get('name')
        })
    except Exception as e:
        current_app.logger.error(f"Error getting user info: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to get user info'}), 500
