from functools import wraps
from flask import jsonify, current_app
from flask_jwt_extended import verify_jwt_in_request, get_jwt

def requires_tenant_access(f):
    """Decorator to check if user has access to the requested tenant."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            # Get tenant ID from URL parameters
            tenant_id = kwargs.get('tenant_id')
            if not tenant_id:
                return jsonify({"error": "Tenant ID not provided"}), 400
                
            # Get user info from JWT
            claims = get_jwt()
            user_tenant = claims.get('tenant_id')
            user_email = claims.get('email')
            user_roles = claims.get('roles', [])
            
            # Log the access check
            current_app.logger.info(
                f"Tenant access check - User: {user_email}, "
                f"Requested Tenant: {tenant_id}, "
                f"User's Tenant: {user_tenant}, "
                f"Roles: {user_roles}"
            )
            
            # Check if user is admin (from example.com) or belongs to the tenant
            is_admin = user_tenant == 'example.com' or 'admin' in user_roles
            
            # Allow access if user is admin or belongs to the tenant
            if not is_admin and user_tenant != tenant_id:
                current_app.logger.warning(
                    f"Access denied - User {user_email} doesn't have access to tenant {tenant_id}"
                )
                return jsonify({"error": "Access denied"}), 403
                
            return f(*args, **kwargs)
            
        except Exception as e:
            current_app.logger.error(f"Error in tenant access check: {str(e)}")
            return jsonify({"error": "Internal server error"}), 500
            
    return decorated_function
