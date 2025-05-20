from flask import Blueprint, jsonify, current_app, redirect, url_for, render_template, session, request, make_response, flash
from flask_jwt_extended import (
    jwt_required, get_jwt, verify_jwt_in_request, get_jwt_identity,
    set_access_cookies, unset_jwt_cookies, create_access_token
)
from functools import wraps
from datetime import datetime, timedelta
import logging
from app.core.extensions import run_sync
from app.models.tenant import Tenant

# Import decorators
from app.core.decorators import requires_tenant_access

logger = logging.getLogger(__name__)

tenant_bp = Blueprint('tenant', __name__)

def get_tenant_from_jwt():
    """Helper to get tenant ID from JWT claims."""
    try:
        verify_jwt_in_request(optional=True)
        claims = get_jwt()
        return claims.get('tenant_id')
    except Exception as e:
        logger.warning(f"Failed to get tenant from JWT: {str(e)}")
        return None

@tenant_bp.route('/<tenant_id>/home')
@jwt_required()
@requires_tenant_access
def tenant_home(tenant_id):
    """Tenant home page."""
    try:
        claims = get_jwt()
        user_info = {
            'email': claims.get('email'),
            'name': claims.get('name'),
            'tenant_id': claims.get('tenant_id'),
            'roles': claims.get('roles', ['user'])
        }
        
        # Get tenant information
        tenant = Tenant.get_by_id(tenant_id)
        if not tenant:
            logger.error(f"Tenant not found: {tenant_id}")
            return jsonify({"error": "Tenant not found"}), 404
        
        return render_template('tenant/home.html',
                             tenant_id=tenant_id,
                             org_id=tenant.organization_id,
                             user_info=user_info)
                             
    except Exception as e:
        logger.error(f"Error accessing tenant home: {str(e)}")
        return jsonify({"error": "Failed to access tenant home"}), 500

@tenant_bp.route('/<tenant_id>/resources')
@jwt_required()
@requires_tenant_access
def list_resources(tenant_id):
    """List tenant resources."""
    try:
        # Get tenant information
        tenant = Tenant.get_by_id(tenant_id)
        if not tenant:
            logger.error(f"Tenant not found: {tenant_id}")
            return jsonify({"error": "Tenant not found"}), 404
            
        # Get resources for the tenant
        resources = [
            {
                'id': 'resource1',
                'name': 'Resource 1',
                'type': 'document',
                'created_at': '2024-01-01T00:00:00Z'
            },
            {
                'id': 'resource2',
                'name': 'Resource 2',
                'type': 'folder',
                'created_at': '2024-01-02T00:00:00Z'
            }
        ]
        
        return jsonify(resources)
        
    except Exception as e:
        logger.error(f"Error listing resources: {str(e)}")
        return jsonify({"error": "Failed to list resources"}), 500

@tenant_bp.route('/<tenant_id>/users')
@jwt_required()
@requires_tenant_access
def list_users(tenant_id):
    """List tenant users."""
    try:
        # Get tenant information
        tenant = Tenant.get_by_id(tenant_id)
        if not tenant:
            logger.error(f"Tenant not found: {tenant_id}")
            return jsonify({"error": "Tenant not found"}), 404
            
        from app.models.user import User
        users = [user for user in User.get_all() if user.tenant_id == tenant_id]
        
        return jsonify([{
            'id': user.id,
            'email': user.email,
            'name': user.name,
            'created_at': user.created_at.isoformat()
        } for user in users])
        
    except Exception as e:
        logger.error(f"Error listing users: {str(e)}")
        return jsonify({"error": "Failed to list users"}), 500
