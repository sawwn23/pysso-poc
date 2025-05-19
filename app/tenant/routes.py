from flask import Blueprint, jsonify, current_app, redirect, url_for, render_template, session, request, make_response, flash
from flask_jwt_extended import (
    jwt_required, get_jwt, verify_jwt_in_request, get_jwt_identity,
    set_access_cookies, unset_jwt_cookies, create_access_token
)
from functools import wraps
from datetime import datetime, timedelta
import logging

# Import decorators
from app.core.decorators import requires_tenant_access, permit_authorize

logger = logging.getLogger(__name__)

tenant_bp = Blueprint('tenant', __name__)

def get_tenant_from_jwt():
    """Helper to get tenant ID from JWT claims."""
    try:
        verify_jwt_in_request(optional=True)
        claims = get_jwt()
        return claims.get('org_id')
    except Exception as e:
        logger.warning(f"Failed to get tenant from JWT: {str(e)}")
        return None

@tenant_bp.route('/<tenant_id>/resources')
@jwt_required()
@requires_tenant_access
@permit_authorize("resource", "read")
def get_tenant_resources(tenant_id):
    """Get resources for a specific tenant."""
    try:
        claims = get_jwt()
        user_tenant = claims.get('org_id')
        user_email = claims.get('sub')
        
        current_app.logger.info(f"User {user_email} accessing resources for tenant {tenant_id}")
        
        # In a real application, fetch this from a database with proper tenant isolation
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
        current_app.logger.error(f"Error fetching tenant resources: {str(e)}")
        return jsonify({
            "msg": "Error fetching resources",
            "error": "resource_fetch_error"
        }), 500

@tenant_bp.route('/<tenant_id>')
@jwt_required()
def tenant_home(tenant_id):
    """Tenant-specific home page with tenant switching for admins."""
    try:
        # Get JWT claims
        claims = get_jwt()
        user_email = claims.get('sub')
        user_roles = claims.get('roles', [])
        
        # Log the incoming request
        current_app.logger.info(f"Tenant home request - User: {user_email}, Tenant: {tenant_id}, Claims: {claims}")
        
        # Check if user has access to this tenant
        user_tenant = claims.get('org_id')
        is_admin = 'admin' in user_roles
        
        # Allow access if user is admin or belongs to the tenant
        if not is_admin and user_tenant != tenant_id:
            current_app.logger.warning(f"Access denied - User {user_email} doesn't have access to tenant {tenant_id}")
            return jsonify({"error": "Access denied"}), 403
        
        # Update session with current tenant context
        session['current_tenant'] = tenant_id
        
        # Prepare user info for the template
        user_info = {
            'email': user_email,
            'name': claims.get('name', user_email.split('@')[0]),
            'roles': user_roles,
            'tenant_id': tenant_id,
            'is_admin': is_admin
        }
        
        # Get list of all tenants for admin switcher
        tenants = []
        if is_admin:
            # In a real app, fetch this from your database
            tenants = [
                {'id': 'company1', 'name': 'Company 1'},
                {'id': 'company2', 'name': 'Company 2'}
            ]
        
        # Create response with updated JWT token
        response = make_response(render_template(
            'tenant/tenant_home.html',
            user_info=user_info,
            tenant_id=tenant_id,
            tenants=tenants
        ))
        
        # Refresh the JWT token to prevent expiration during active sessions
        new_token = create_access_token(
            identity=user_email,
            additional_claims={
                'org_id': tenant_id,
                'roles': user_roles,
                'name': user_info['name']
            }
        )
        set_access_cookies(response, new_token)
        
        return response
        
    except Exception as e:
        current_app.logger.error(f"Error in tenant_home: {str(e)}", exc_info=True)
        flash('An error occurred while loading the dashboard. Please try again.', 'error')
        return redirect(url_for('auth.login'))
