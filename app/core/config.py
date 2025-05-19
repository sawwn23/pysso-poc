from flask import current_app
import logging
from dotenv import load_dotenv
import os

class Config:
    """Application configuration class"""
    load_dotenv()
    
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
    
    # Validate required environment variables
    missing_vars = [var for var in REQUIRED_ENV_VARS if not os.getenv(var)]
    if missing_vars:
        raise RuntimeError(f"Missing required environment variables: {', '.join(missing_vars)}")
    
    # Flask configuration
    SECRET_KEY = os.getenv('SECRET_KEY')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
    JWT_ACCESS_TOKEN_EXPIRES = int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', 3600))
    JWT_TOKEN_LOCATION = ['cookies', 'headers']
    JWT_COOKIE_SECURE = os.getenv('FLASK_ENV') == 'production'
    JWT_COOKIE_CSRF_PROTECT = True
    JWT_CSRF_CHECK_FORM = True
    
    # SSOReady configuration
    SSOREADY_API_KEY = os.getenv('SSOREADY_API_KEY')
    SSOREADY_ORGANIZATION_ID = os.getenv('SSOREADY_ORGANIZATION_ID')
    SSOREADY_BASE_URL = os.getenv('SSOREADY_BASE_URL', 'https://api.ssoready.com')
    
    # Permit.io configuration
    PERMIT_SDK_TOKEN = os.getenv('PERMIT_SDK_TOKEN')
    PERMIT_PDP_URL = os.getenv('PERMIT_PDP_URL')
    PERMIT_API_URL = os.getenv('PERMIT_API_URL')
    
    # Application configuration
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
