from functools import wraps
from flask import jsonify, request
from flask_jwt_extended import verify_jwt_in_request, get_jwt

def permit_authorize(resource, action):
    """
    Decorator to check if the user has permission to perform an action on a resource.
    
    Args:
        resource (str): The resource being accessed (e.g., 'document', 'user')
        action (str): The action being performed (e.g., 'read', 'write', 'delete')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # First verify JWT is present
            verify_jwt_in_request()
            
            # Get JWT claims
            claims = get_jwt()
            
            # Check for super admin (has all permissions)
            if claims.get('roles') and 'super_admin' in claims['roles']:
                return f(*args, **kwargs)
                
            # Get user's permissions from JWT
            user_permissions = set()
            for role in claims.get('roles', []):
                # Get permissions for each role from the JWT claims
                role_permissions = claims.get('permissions', {}).get(role, [])
                user_permissions.update(role_permissions)
            
            # Check for wildcard permission
            if '*' in user_permissions or f"{resource}:*" in user_permissions or f"*:{action}" in user_permissions:
                return f(*args, **kwargs)
                
            # Check for specific permission
            required_permission = f"{resource}:{action}"
            if required_permission not in user_permissions:
                return jsonify({"error": f"Insufficient permissions. Required: {required_permission}"}), 403
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def requires_roles(*required_roles):
    """
    Decorator to check if the user has any of the required roles.
    
    Args:
        *required_roles (str): One or more role names that are allowed
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            user_roles = set(claims.get('roles', []))
            
            # Check if any of the user's roles match the required roles
            if not any(role in user_roles for role in required_roles):
                return jsonify({"error": "Insufficient role permissions"}), 403
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator
