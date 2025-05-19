from functools import wraps
from flask import jsonify, current_app
from flask_jwt_extended import verify_jwt_in_request, get_jwt

# Use a lazy import for permit to avoid circular imports
permit = None

__all__ = ["permit_authorize", "requires_tenant_access"]

def permit_authorize(resource, action):
    """Simple decorator to check Permit.io authorization"""
    def wrapper(fn):
        @wraps(fn)
        async def decorated(*args, **kwargs):
            global permit
            if permit is None:
                from app.core.extensions import permit as _permit
                permit = _permit
                
            try:
                verify_jwt_in_request()
                claims = get_jwt()
                user_email = claims.get('sub')
                user_tenant = claims.get('tenant_id')
                
                if 'tenant_id' in kwargs and resource != 'admin':
                    requested_tenant = kwargs['tenant_id']
                    if not 'admin' in claims.get('roles', []) and requested_tenant != user_tenant:
                        return jsonify({"error": "tenant_mismatch"}), 403
                        
                user = {
                    "key": user_email,
                    "email": user_email,
                    "tenant": user_tenant,
                    "roles": claims.get('roles', [])
                }
                
                context = {
                    "tenant": kwargs.get('tenant_id', user_tenant),
                    "environment": current_app.config.get('FLASK_ENV', 'development')
                }
                
                if not permit or not hasattr(permit, 'check'):
                    current_app.logger.error("Permit not initialized or check method not available")
                    return jsonify({"error": "permit_not_initialized"}), 500
                    
                if not permit.check(user, action, resource, context):
                    current_app.logger.warning(f"Permission denied for {user_email} on {resource}/{action}")
                    return jsonify({"error": "permission_denied"}), 403
                    
                return fn(*args, **kwargs)
                
            except Exception as e:
                current_app.logger.error(f"Auth error in permit_authorize: {str(e)}", exc_info=True)
                return jsonify({"error": "auth_error"}), 500
                
        return decorated
    return wrapper

def requires_tenant_access(f):
    """
    Decorator to check if the user has access to the requested tenant.
    Admins have access to all tenants.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            # Verify JWT is present and valid
            verify_jwt_in_request()
            claims = get_jwt()
            
            # Get tenant_id from route parameters
            tenant_id = kwargs.get('tenant_id')
            if not tenant_id:
                current_app.logger.warning("No tenant_id provided in route parameters")
                return jsonify({"error": "tenant_id_required"}), 400
            
            # Get user's tenant from JWT claims
            user_tenant = claims.get('tenant_id')
            user_email = claims.get('sub', 'unknown')
            user_roles = claims.get('roles', [])
            
            # Log access attempt
            current_app.logger.info(
                f"Tenant access check - User: {user_email}, "
                f"Requested Tenant: {tenant_id}, "
                f"User's Tenant: {user_tenant}, "
                f"Roles: {user_roles}"
            )
            
            # Admin users can access any tenant
            if 'admin' in user_roles:
                current_app.logger.debug(f"Admin access granted to tenant {tenant_id}")
                return f(*args, **kwargs)
            
            # Regular users can only access their own tenant
            if user_tenant != tenant_id:
                current_app.logger.warning(
                    f"Access denied - User {user_email} (tenant: {user_tenant}) "
                    f"tried to access tenant {tenant_id}"
                )
                return jsonify({
                    "error": "access_denied",
                    "message": "You don't have permission to access this tenant"
                }), 403
                
            # User has access to this tenant
            return f(*args, **kwargs)
            
        except Exception as e:
            current_app.logger.error(
                f"Error in requires_tenant_access: {str(e)}",
                exc_info=True
            )
            return jsonify({
                "error": "authorization_error",
                "message": "An error occurred while verifying your access"
            }), 500
            
    return decorated
