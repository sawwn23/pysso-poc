from flask import Blueprint, jsonify, current_app, render_template, request
from flask_jwt_extended import jwt_required, get_jwt
from datetime import datetime
import logging
from app.models.tenant import Tenant

admin_bp = Blueprint('admin', __name__)
logger = logging.getLogger(__name__)

@admin_bp.route('/tenants')
@jwt_required()
def list_tenants():
    """List all tenants (admin only)."""
    try:
        # Get user info from JWT
        claims = get_jwt()
        email = claims.get('email')
        roles = claims.get('roles', [])
        
        # Check if user is admin
        if 'admin' not in roles:
            logger.warning(f"Non-admin user {email} attempted to access tenant list")
            return jsonify({"error": "Admin access required"}), 403
            
        logger.info("Admin accessing tenant list")
        
        # Get all tenants from the database
        tenants = Tenant.get_all()
        tenant_list = [tenant.to_dict() for tenant in tenants]
                
        logger.info(f"Admin {email} retrieved tenant list")
        
        # Check if the request wants JSON
        if request.headers.get('Accept') == 'application/json':
            return jsonify(tenant_list)
            
        # Otherwise render the template
        return render_template('admin/tenants.html', tenants=tenant_list)
        
    except Exception as e:
        logger.error(f"Error listing tenants: {str(e)}")
        return jsonify({"error": "Failed to list tenants"}), 500
