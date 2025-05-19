import os
import json
import logging
from pathlib import Path
from functools import lru_cache
from dotenv import load_dotenv

# Set up logging
logger = logging.getLogger(__name__)

# Load environment variables from .env file if it exists
env_path = Path(__file__).parent.parent.parent / '.env'
if env_path.exists():
    load_dotenv(dotenv_path=env_path, override=True)
    logger.info("Loaded environment variables from .env file")
else:
    logger.warning("No .env file found. Using system environment variables.")

# Required environment variables
REQUIRED_ENV_VARS = [
    "SECRET_KEY",
    "JWT_SECRET_KEY",
    "SSOREADY_API_KEY",
    "SSOREADY_ORGANIZATION_ID",
    "PERMIT_SDK_TOKEN",
    "PERMIT_PDP_URL",
    "PERMIT_API_URL"
]

# Log environment variable status for debugging
for var in REQUIRED_ENV_VARS:
    logger.debug(f"{var}: {'Set' if os.getenv(var) else 'Not set'}")

class Config:
    def __init__(self):
        self.config_path = Path(__file__).parent / 'config.json'
        self._validate_env_vars()
        self._load_config()
    
    def _validate_env_vars(self):
        """Validate required environment variables"""
        missing_vars = [var for var in REQUIRED_ENV_VARS if not os.getenv(var)]
        if missing_vars:
            raise RuntimeError(f"Missing required environment variables: {', '.join(missing_vars)}")
    
    def _load_config(self):
        """Load configuration from config.json"""
        try:
            with open(self.config_path) as f:
                self.data = json.load(f)
        except FileNotFoundError:
            # Initialize with default structure if config doesn't exist
            self.data = {
                "organizations": {}
            }
            self._save_config()
    
    def _save_config(self):
        """Save configuration to config.json"""
        with open(self.config_path, 'w') as f:
            json.dump(self.data, f, indent=2)
    
    @property
    def jwt_secret_key(self):
        return os.getenv("JWT_SECRET_KEY")
    
    @property
    def jwt_access_token_expires(self):
        return int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES", 3600))
    
    @property
    def sso_ready_config(self):
        return {
            "api_key": os.getenv("SSOREADY_API_KEY"),
            "organization_id": os.getenv("SSOREADY_ORGANIZATION_ID")
        }
    
    @property
    def permit_config(self):
        return {
            "token": os.getenv("PERMIT_SDK_TOKEN"),
            "pdp": os.getenv("PERMIT_PDP_URL"),
            "api_url": os.getenv("PERMIT_API_URL")
        }
    
    @lru_cache(maxsize=32)
    def get_organization_by_domain(self, domain):
        """Get organization settings by domain with caching"""
        for org_id, org_data in self.data.get('organizations', {}).items():
            if domain in org_data.get('domains', []):
                return {
                    'id': org_id,
                    'name': org_data.get('name', 'Unknown Organization'),
                    'domains': org_data.get('domains', []),
                    'roles': org_data.get('roles', []),
                    'permissions': org_data.get('permissions', {})
                }
        return None
    
    def get_organization_roles(self, org_id):
        """Get roles for an organization"""
        org = self.data.get('organizations', {}).get(org_id, {})
        return org.get('roles', [])
    
    def get_role_permissions(self, org_id, role_name):
        """Get permissions for a specific role in an organization"""
        org = self.data.get('organizations', {}).get(org_id, {})
        for role in org.get('roles', []):
            if role.get('name') == role_name:
                return role.get('permissions', [])
        return []

# Create a singleton instance
config = Config()
