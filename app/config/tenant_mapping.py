"""Tenant mapping configuration"""

TENANT_MAPPING = {
    "company1.com": "tenant1",
    "company2.com": "tenant2",
    "example.com": "admin"
}

def get_tenant_info(domain):
    """Get tenant info from email domain"""
    return TENANT_MAPPING.get(domain)
