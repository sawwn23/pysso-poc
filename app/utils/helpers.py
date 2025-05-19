from datetime import datetime
from flask import current_app

def get_tenant_id(email):
    """Extract tenant ID from email domain and transform it to match tenant format"""
    domain = email.split('@')[1]
    # Replace dots with underscores and make lowercase
    return domain.replace('.', '_').lower()

def verify_sso_response(response):
    """Verify the SSO response and return user info."""
    if not response or not hasattr(response, 'email'):
        raise ValueError("Invalid SSO response: missing email")
    
    user_info = {
        'email': response.email,
        'name': response.email.split('@')[0],
        'picture': None,
        'authenticated': True,
        'timestamp': datetime.now().isoformat()
    }
    
    return user_info
