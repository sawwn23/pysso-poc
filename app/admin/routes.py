from flask import Blueprint, jsonify, current_app, request
from flask_jwt_extended import jwt_required, get_jwt
from app.core.decorators import permit_authorize

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/tenants')
@jwt_required()
@permit_authorize("admin", "access")
def list_tenants():
    """List all tenants. Requires admin access."""
    try:
        current_app.logger.info("Admin accessing tenant list")
        claims = get_jwt()
        user_email = claims.get('sub')
        
        # Get tenants from the tenant mapping
        from app.config.tenant_mapping import TENANT_MAPPING
        tenants = [
            {'id': info['id'], 'name': info['name']} 
            for info in TENANT_MAPPING.values()
        ]
        
        current_app.logger.info(f"Admin {user_email} retrieved tenant list")
        return jsonify({
            'tenants': tenants,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        current_app.logger.error(f"Error listing tenants: {str(e)}")
        return jsonify({
            "msg": "Error fetching tenants",
            "error": "tenant_fetch_error"
        }), 500
