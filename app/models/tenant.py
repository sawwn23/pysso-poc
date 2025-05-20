from datetime import datetime
from flask import current_app
from app.config.config import Config

class Tenant:
    """Tenant model for multi-tenancy support using in-memory storage."""
    
    # In-memory storage for tenants
    _tenants = {}
    
    def __init__(self, id, name):
        self.id = id
        self.name = name
        org_config = Config.get_organization(id)
        self.organization_id = org_config.get('organization_id') if org_config else None
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
        
        # Store in memory
        self._tenants[id] = self

    @classmethod
    def get_by_id(cls, tenant_id):
        """Get tenant by ID."""
        return cls._tenants.get(tenant_id)

    @classmethod
    def get_by_organization_id(cls, organization_id):
        """Get tenant by organization ID."""
        for tenant in cls._tenants.values():
            if tenant.organization_id == organization_id:
                return tenant
        return None

    @classmethod
    def get_all(cls):
        """Get all tenants."""
        return list(cls._tenants.values())

    def to_dict(self):
        """Convert tenant to dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'organization_id': self.organization_id,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

    @classmethod
    def create_initial_tenants(cls):
        """Create initial tenants for POC."""
        # Create tenants from ORGANIZATIONS config
        for domain, org_config in Config.ORGANIZATIONS.items():
            cls(domain, org_config['name']) 