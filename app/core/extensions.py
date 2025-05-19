# filepath: /home/sawwinnaung/CascadeProjects/python-ssoready-app/app/core/extensions.py
import os
from permit import Permit
from ssoready.client import SSOReady
from flask import current_app
import asyncio
from app.core.config import Config

def run_sync(coro):
    """Run an async coroutine synchronously"""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    return loop.run_until_complete(coro)

# Resource types for Permit.io
RESOURCE_TYPES = {
    "tenant": ["read", "write", "delete"],
    "resource": ["read", "write", "delete"],
    "admin": ["access"]
}

# Global instances
permit = None
sso_client = None

def init_extensions(app):
    """Initialize Flask extensions"""
    global permit, sso_client
    
    try:
        # Initialize Permit.io client with configuration
        permit = Permit(
            token=app.config.get('PERMIT_SDK_TOKEN') or os.getenv('PERMIT_SDK_TOKEN'),
            pdp="https://cloudpdp.api.permit.io",  # Use cloud PDP URL
            api_url=app.config.get('PERMIT_API_URL') or os.getenv('PERMIT_API_URL')
        )
        
        # Configure PDP settings
        try:
            # Set up cloud PDP configuration
            pdp_config = {
                "key": "cloud",
                "name": "Cloud PDP",
                "description": "Cloud PDP for RBAC",
                "policy_type": "RBAC",
                "environment": app.config.get('FLASK_ENV', 'development'),
                "pdp_url": "https://cloudpdp.api.permit.io"
            }
            
            # Create or update PDP configuration - Fixed API call
            try:
                # Check if the permit SDK has the pdp attribute
                if hasattr(permit.api, 'pdp'):
                    pdp = run_sync(permit.api.pdp.get("cloud"))
                    if pdp:
                        run_sync(permit.api.pdp.update("cloud", pdp_config))
                        app.logger.info("Updated cloud PDP configuration")
                    else:
                        run_sync(permit.api.pdp.create(pdp_config))
                        app.logger.info("Created cloud PDP configuration")
                else:
                    app.logger.warning("PDP configuration not available in this Permit SDK version")
            except Exception as e:
                if "not found" in str(e).lower():
                    if hasattr(permit.api, 'pdp'):
                        run_sync(permit.api.pdp.create(pdp_config))
                        app.logger.info("Created cloud PDP configuration")
                else:
                    raise
                    
        except Exception as e:
            app.logger.warning(f"Could not configure PDP: {str(e)}")
        
        # Initialize resources and roles
        init_permit_resources()
        app.logger.info("Permit.io client initialized successfully")
        
        # Initialize SSOReady client if API key is configured
        global sso_client
        sso_api_key = app.config.get('SSOREADY_API_KEY') or os.getenv('SSOREADY_API_KEY')
        sso_org_id = app.config.get('SSOREADY_ORGANIZATION_ID') or os.getenv('SSOREADY_ORGANIZATION_ID')
        
        app.logger.info(f"SSO Configuration - API Key: {'Set' if sso_api_key else 'Not set'}, Org ID: {'Set' if sso_org_id else 'Not set'}")
        
        if not sso_api_key or not sso_org_id:
            missing = []
            if not sso_api_key:
                missing.append("SSOREADY_API_KEY")
            if not sso_org_id:
                missing.append("SSOREADY_ORGANIZATION_ID")
                
            app.logger.warning(f"SSO features disabled. Missing required configuration: {', '.join(missing)}")
            sso_client = None
            return
            
        try:
            sso_base_url = app.config.get('SSOREADY_BASE_URL') or os.getenv('SSOREADY_BASE_URL', 'https://api.ssoready.com')
            app.logger.info(f"Initializing SSOReady client with base URL: {sso_base_url}")
            
            # Initialize SSOReady client directly
            sso_client = SSOReady(
                api_key=sso_api_key,
                base_url=sso_base_url
            )

            # Store the initialized client in app.extensions
            app.extensions['sso_client'] = sso_client
            
            # Log success
            app.logger.info("SSOReady client initialized successfully")
                
        except Exception as e:
            app.logger.error(f"Failed to initialize SSOReady client: {str(e)}", exc_info=True)
            sso_client = None
        
    except Exception as e:
        app.logger.error(f"Failed to initialize extensions: {str(e)}")
        raise

def sync_user_with_permit(user_email, tenant_id):
    """
    Sync a user with Permit.io, creating them if they don't exist
    and assigning appropriate roles based on their tenant.
    """
    try:
        users_api = permit.api.users
        try:
            # First, try to create the user - this is more efficient than checking existence first
            user_data = {
                "email": user_email,
            }
            
            # Assign role to user
            role = "role_admin" if tenant_id == "default" else "role_user"
            
            try:
                # Get or create tenant
                try:
                    tenant = run_sync(permit.api.tenants.get(tenant_id))
                    current_app.logger.info(f"Found existing tenant: {tenant_id}")
                except Exception as e:
                    if "not found" in str(e).lower():
                        # Create new tenant
                        tenant_data = {
                            "key": tenant_id,
                            "name": tenant_id,
                            "description": f"Tenant for {tenant_id}",
                            "attributes": {
                                "organization_id": tenant_id
                            }
                        }
                        tenant = run_sync(permit.api.tenants.create(tenant_data))
                        current_app.logger.info(f"Created new tenant: {tenant_id}")
                    else:
                        raise
                
                role_assignment = {
                    "user": user_email,
                    "role": role,
                    "tenant": tenant_id
                }
                try:
                    run_sync(permit.api.users.assign_role(role_assignment))
                    current_app.logger.info(f"Assigned role {role} to user {user_email}")
                except Exception as e:
                    if "already exists" not in str(e).lower():
                        current_app.logger.error(f"Error assigning role to user: {str(e)}")
                        raise
                    else:
                        current_app.logger.info(f"Role {role} already assigned to user {user_email}")
            except Exception as e:
                if "already exists" not in str(e).lower():
                    current_app.logger.error(f"Error assigning role to user: {str(e)}")
                    raise
                else:
                    current_app.logger.info(f"Role {role} already assigned to user {user_email}")
            
            # Try to create the user first
            try:
                run_sync(users_api.create(user_data))
                current_app.logger.info(f"Created new user: {user_email}")
            except Exception as create_error:
                if "already exists" in str(create_error).lower():
                    # User exists, try to update
                    try:
                        run_sync(users_api.update(user_email, user_data))
                        current_app.logger.info(f"Updated existing user: {user_email}")
                    except Exception as update_error:
                        current_app.logger.error(f"Error updating user: {str(update_error)}")
                        raise
                else:
                    current_app.logger.error(f"Error creating user: {str(create_error)}")
                    raise
            
            current_app.logger.info(f"Successfully synced user {user_email} with Permit.io")
            
        except Exception as e:
            current_app.logger.error(f"Error syncing user with Permit.io: {str(e)}", exc_info=True)
            raise
        
    except Exception as e:
        current_app.logger.error(f"Error syncing user with Permit.io: {str(e)}", exc_info=True)
        raise


def init_tenants():
    """
    Initialize tenants based on configuration.
    This function creates tenants from the configuration data.
    """
    try:
        tenants_api = permit.api.tenants
        
        # Get all existing tenants
        existing_tenants = run_sync(tenants_api.list())
        existing_tenant_keys = {t.key: t for t in existing_tenants}
        current_app.logger.debug(f"Found existing tenants: {list(existing_tenant_keys.keys())}")
        
        # Get tenants from configuration
        config = Config()
        organizations = config.data.get("organizations", {})
        
        for org_id, org_data in organizations.items():
            tenant_key = org_id
            tenant_name = org_data.get("name", org_id)
            tenant_description = org_data.get("description", f"Tenant for {org_id}")
            
            try:
                # Try to get or create the tenant
                if tenant_key in existing_tenant_keys:
                    # Update existing tenant
                    try:
                        run_sync(tenants_api.update(tenant_key, {
                            "name": tenant_name,
                            "description": tenant_description,
                            "attributes": {
                                "organization_id": org_id
                            }
                        }))
                        current_app.logger.info(f"Updated tenant: {tenant_key}")
                    except Exception as update_error:
                        if "not found" in str(update_error).lower():
                            # Tenant doesn't exist, create it
                            try:
                                tenant_data = {
                                    "key": tenant_key,
                                    "name": tenant_name,
                                    "description": tenant_description,
                                    "attributes": {
                                        "organization_id": org_id
                                    }
                                }
                                run_sync(tenants_api.create(tenant_data))
                                current_app.logger.info(f"Created tenant: {tenant_key}")
                            except Exception as create_error:
                                current_app.logger.error(f"Error creating tenant {tenant_key}: {str(create_error)}")
                                raise
                        else:
                            current_app.logger.error(f"Error updating tenant {tenant_key}: {str(update_error)}")
                            raise
                else:
                    # Create new tenant
                    try:
                        tenant_data = {
                            "key": tenant_key,
                            "name": tenant_name,
                            "description": tenant_description,
                            "attributes": {
                                "organization_id": org_id
                            }
                        }
                        run_sync(tenants_api.create(tenant_data))
                        current_app.logger.info(f"Created tenant: {tenant_key}")
                    except Exception as create_error:
                        current_app.logger.error(f"Error creating tenant {tenant_key}: {str(create_error)}")
                        raise
            except Exception as e:
                current_app.logger.error(f"Error processing tenant {tenant_key}: {str(e)}")
                continue
        
        current_app.logger.info("Successfully initialized all tenants")
        
    except Exception as e:
        current_app.logger.error(f"Error in init_tenants: {str(e)}", exc_info=True)
        raise


def init_permit_resources():
    """
    Initialize Permit.io resources and roles.
    This function handles the creation of resources, roles, and permissions
    in a way that's idempotent and handles errors gracefully.
    """
    try:
        resources_api = permit.api.resources
        
        # Get all existing resources
        existing_resources = run_sync(resources_api.list())
        existing_resource_keys = {r.key: r for r in existing_resources}
        current_app.logger.debug(f"Found existing resources: {list(existing_resource_keys.keys())}")
        
        # Ensure all required resources exist with their actions
        for resource_key, actions in RESOURCE_TYPES.items():
            # Skip if resource already exists
            if resource_key in existing_resource_keys:
                current_app.logger.debug(f"Resource {resource_key} already exists, skipping creation")
                continue
                
            try:
                resource_data = {
                    "key": resource_key,
                    "name": f"{resource_key.capitalize()} Resource",
                    "description": f"{resource_key.capitalize()} resource type",
                    "type": resource_key,  # Set the type explicitly
                    "actions": actions,
                    "attributes": {}
                }
                run_sync(resources_api.create(resource_data))
                current_app.logger.info(f"Created resource: {resource_key}")
            except Exception as e:
                current_app.logger.error(f"Error creating resource {resource_key}: {str(e)}")
                # Continue with other resources even if one fails
                continue

        # Now initialize roles and permissions
        _init_roles()
            
        # Sync the PDP after all changes - Fixed API call
        try:
            # Check if the SDK version supports pdp_config
            if hasattr(permit.api, 'pdp_config'):
                run_sync(permit.api.pdp_config.sync_config())
                current_app.logger.info("Synchronized PDP configuration")
            elif hasattr(permit, 'sync'):
                # Alternative sync method for different SDK versions
                run_sync(permit.sync())
                current_app.logger.info("Synchronized Permit configuration")
            else:
                current_app.logger.warning("PDP sync not available in this Permit SDK version")
        except Exception as e:
            current_app.logger.warning(f"Could not sync PDP configuration: {str(e)}")
        
        current_app.logger.info("Successfully initialized all Permit.io resources and roles")
        
    except Exception as e:
        current_app.logger.error(f"Error in init_permit_resources: {str(e)}", exc_info=True)
        raise

# Define roles initialization at module level
def _init_roles():
    """
    Initialize roles and assign permissions.
    This function creates or updates roles and assigns appropriate permissions.
    """
    try:
        roles_api = permit.api.roles
        
        # First, get existing roles
        try:
            existing_roles = run_sync(roles_api.list())
            existing_role_keys = {r.key: r for r in existing_roles}
            current_app.logger.debug(f"Found existing roles: {list(existing_role_keys.keys())}")
        except Exception as e:
            current_app.logger.error(f"Error getting existing roles: {str(e)}")
            raise
            
        roles_to_create = [
            {
                "key": "role_user",
                "name": "User",
                "description": "Regular user with basic access",
                "attributes": {
                    "type": "user"
                }
            },
            {
                "key": "role_admin",
                "name": "Administrator",
                "description": "System administrator with full access",
                "attributes": {
                    "type": "admin"
                }
            }
        ]

        # Create or update roles
        for role_data in roles_to_create:
            role_key = role_data["key"]
            try:
                # Try to create the role first (more efficient)
                try:
                    run_sync(roles_api.create(role_data))
                    current_app.logger.info(f"Created role: {role_key}")
                except Exception as create_error:
                    if "already exists" in str(create_error).lower():
                        # Role exists, try to update
                        try:
                            run_sync(roles_api.update(role_key, {
                                "name": role_data["name"],
                                "description": role_data["description"],
                                "attributes": role_data["attributes"]
                            }))
                            current_app.logger.info(f"Updated role: {role_key}")
                        except Exception as update_error:
                            current_app.logger.error(f"Error updating role {role_key}: {str(update_error)}")
                            raise
                    else:
                        current_app.logger.error(f"Error creating role {role_key}: {str(create_error)}")
                        raise
            except Exception as e:
                current_app.logger.error(f"Error processing role {role_key}: {str(e)}")
                raise

            # Assign permissions based on role
            if role_key == 'role_admin':
                try:
                    # Get all resources
                    resources = run_sync(permit.api.resources.list())
                    current_app.logger.debug(f"Found {len(resources)} resources to assign permissions for admin")
                    
                    # Assign all permissions to admin
                    for resource in resources:
                        if not hasattr(resource, 'actions') or not resource.actions:
                            current_app.logger.warning(f"Resource {getattr(resource, 'key', 'unknown')} has no actions")
                            continue
                            
                        for action in resource.actions:
                            try:
                                run_sync(permit.api.role_permissions.assign(
                                    role_key=role_key,
                                    resource_key=resource.key,
                                    action=action
                                ))
                                current_app.logger.debug(f"Assigned {action} on {resource.key} to {role_key}")
                            except Exception as perm_error:
                                if "already exists" not in str(perm_error).lower():
                                    current_app.logger.error(f"Error assigning {action} on {resource.key} to {role_key}: {str(perm_error)}")
                                    raise
                                else:
                                    current_app.logger.debug(f"Permission {action} on {resource.key} already assigned to {role_key}")
                except Exception as e:
                    current_app.logger.error(f"Error assigning permissions to admin role: {str(e)}")
                    raise
            
            # For user role, assign read permissions
            elif role_key == 'role_user':
                try:
                    resources = run_sync(permit.api.resources.list())
                    current_app.logger.debug(f"Found {len(resources)} resources to assign read permissions for user")
                    
                    for resource in resources:
                        if not hasattr(resource, 'actions') or not resource.actions:
                            continue
                            
                        if 'read' in resource.actions:
                            try:
                                run_sync(permit.api.role_permissions.assign(
                                    role_key=role_key,
                                    resource_key=resource.key,
                                    action='read'
                                ))
                                current_app.logger.debug(f"Assigned read permission on {resource.key} to {role_key}")
                            except Exception as perm_error:
                                if "already exists" not in str(perm_error).lower():
                                    current_app.logger.error(f"Error assigning read permission on {resource.key} to {role_key}: {str(perm_error)}")
                                    raise
                                else:
                                    current_app.logger.debug(f"Read permission on {resource.key} already assigned to {role_key}")
                except Exception as e:
                    current_app.logger.error(f"Error assigning permissions to user role: {str(e)}")
                    raise
        
    except Exception as e:
        current_app.logger.error(f"Error in _init_roles: {str(e)}", exc_info=True)
        # Don't re-raise to allow the application to start even if role initialization fails
        # The application can still function with default permissions