from app.core.extensions import permit
from flask import current_app

# Define resources in Permit.io
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
        current_app.logger.warning(f"Permit.io initialization error (may already exist): {str(e)}")
