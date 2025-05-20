from flask import current_app
import logging
from dotenv import load_dotenv
import os
import json
from pathlib import Path
from functools import lru_cache
from datetime import timedelta

# Set up logging
logger = logging.getLogger(__name__)

class Config:
    """Application configuration class"""
    load_dotenv()
    
    # Required environment variables
    REQUIRED_ENV_VARS = [
        "SECRET_KEY",
        "JWT_SECRET_KEY",
        "SSOREADY_API_KEY"
    ]
    
    # Validate required environment variables
    missing_vars = [var for var in REQUIRED_ENV_VARS if not os.getenv(var)]
    if missing_vars:
        raise RuntimeError(f"Missing required environment variables: {', '.join(missing_vars)}")
    
    # Flask configuration
    SECRET_KEY = os.getenv('SECRET_KEY')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_TOKEN_LOCATION = ['cookies']
    JWT_COOKIE_SECURE = False  # Set to True in production
    JWT_COOKIE_CSRF_PROTECT = False  # Set to True in production
    JWT_SESSION_COOKIE = False
    JWT_COOKIE_DOMAIN = None  # Set to your domain in production
    
    # SSOReady configuration
    SSOREADY_API_KEY = os.getenv('SSOREADY_API_KEY')
    SSOREADY_ORGANIZATION_ID = os.getenv('SSOREADY_ORGANIZATION_ID')
    SSOREADY_BASE_URL = os.getenv('SSOREADY_BASE_URL', 'https://api.ssoready.com')
    
    # Application configuration
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    
    # Organization configuration
    ORGANIZATIONS = {
        "example.com": {
            "name": "Example Organization",
            "description": "Admin organization",
            "is_admin": True,
            "organization_id": "org_cd48zxghyarm0zr3sp349p59r"
        },
        "company1.com": {
            "name": "Company 1",
            "description": "Company 1 organization",
            "is_admin": False,
            "organization_id": "org_cd48zxghyarm0zr3sp349p59r"
        },
        "company2.com": {
            "name": "Company 2",
            "description": "Company 2 organization",
            "is_admin": False,
            "organization_id": "org_cd48zxghyarm0zr3sp349p59r"
        }
    }
    
    @classmethod
    def get_organization(cls, domain):
        """Get organization configuration by domain."""
        return cls.ORGANIZATIONS.get(domain)
    
    @classmethod
    def is_admin_organization(cls, domain):
        """Check if an organization is an admin organization."""
        org = cls.get_organization(domain)
        return org and org.get('is_admin', False)
    
    @classmethod
    def get_all_organizations(cls):
        """Get all organization configurations."""
        return cls.ORGANIZATIONS
    
    @classmethod
    def get_admin_organizations(cls):
        """Get all admin organizations."""
        return {
            domain: org for domain, org in cls.ORGANIZATIONS.items()
            if org.get('is_admin', False)
        }
    
    @classmethod
    def get_regular_organizations(cls):
        """Get all non-admin organizations."""
        return {
            domain: org for domain, org in cls.ORGANIZATIONS.items()
            if not org.get('is_admin', False)
        }

# Create a singleton instance
config = Config()
