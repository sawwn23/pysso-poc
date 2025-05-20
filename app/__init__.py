import logging
import os
from datetime import datetime, timedelta
from pathlib import Path
from dotenv import load_dotenv

from flask import Flask, jsonify, request, session, render_template, redirect, url_for, current_app
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required, set_access_cookies, unset_jwt_cookies, get_jwt
from flask_login import LoginManager
from ssoready.client import SSOReady

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables first
env_path = Path(__file__).parent.parent / '.env'
if env_path.exists():
    load_dotenv(dotenv_path=env_path, override=True)
    logger.info(f"Loaded environment variables from {env_path}")
else:
    logger.warning(f"No .env file found at {env_path}")

# Initialize Flask extensions
jwt = JWTManager()
login_manager = LoginManager()

# Import and initialize config
from app.config.config import config as app_config, Config

# Import core extensions
from app.core import init_extensions, sso_client as core_sso_client
from app.models.user import User

# Import blueprints
from app.main.routes import main_bp
from app.auth.routes import auth_bp
from app.admin.routes import admin_bp
from app.tenant.routes import tenant_bp

# Initialize glob
sso_client = None

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login"""
    return User.get_by_id(user_id)

def page_not_found(e):
    """404 error handler"""
    return render_template('errors/404.html'), 404

def internal_server_error(e):
    """500 error handler"""
    return render_template('errors/500.html'), 500

def create_app(config_class=Config):
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions
    jwt.init_app(app)
    login_manager.init_app(app)
    
    # Initialize SSOReady client using init_extensions
    init_extensions(app)
    global sso_client
    sso_client = app.extensions.get('sso_client')
    
    # Create initial tenants for POC
    from app.models.tenant import Tenant
    Tenant.create_initial_tenants()

    # Register blueprints
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(admin_bp, url_prefix='/api/admin')
    app.register_blueprint(tenant_bp, url_prefix='/api/tenant')

    # Register error handlers
    app.register_error_handler(404, page_not_found)
    app.register_error_handler(500, internal_server_error)

    return app
