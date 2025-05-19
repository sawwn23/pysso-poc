import logging
import os
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, jsonify, request, session, render_template, redirect, url_for, current_app
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required, set_access_cookies, unset_jwt_cookies, get_jwt

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize JWT
jwt = JWTManager()

# Import and initialize config
from app.config.config import config as app_config

# Import core extensions
from app.core import init_extensions, init_permit_resources, permit, sso_client as core_sso_client

# Initialize global variables
sso_client = None
permit = None

def create_app():
    """Create and configure the Flask application"""
    app = Flask(__name__)
    
    # Basic config
    app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key-please-change-in-production")
    app.config.update(
        # Security
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=timedelta(days=1),
        
        # JWT Configuration
        JWT_SECRET_KEY=app_config.jwt_secret_key,
        JWT_ACCESS_TOKEN_EXPIRES=timedelta(seconds=app_config.jwt_access_token_expires),
        JWT_TOKEN_LOCATION=['cookies'],
        JWT_COOKIE_SECURE=False,  # Set to True in production with HTTPS
        JWT_COOKIE_CSRF_PROTECT=False,  # Disabled for POC
        JWT_CSRF_IN_COOKIES=False,  # Disabled for POC
        JWT_COOKIE_NAME='access_token_cookie',
        JWT_COOKIE_DOMAIN=None,
        JWT_COOKIE_SAMESITE='Lax',
        JWT_SESSION_COOKIE=False,
        JWT_COOKIE_PATH='/',
        JWT_ALGORITHM='HS256',
        
        # CSRF Protection - Disabled for POC
        WTF_CSRF_ENABLED=False,
        
        # Logging
        LOG_LEVEL=os.getenv("LOG_LEVEL", "INFO").upper(),
        
        # SSO Configuration
        SSOREADY_API_KEY=os.getenv('SSOREADY_API_KEY'),
        SSOREADY_ORGANIZATION_ID=os.getenv('SSOREADY_ORGANIZATION_ID'),
        SSOREADY_BASE_URL=os.getenv('SSOREADY_BASE_URL', 'https://api.ssoready.com'),
        SSOREADY_ORG_NAME=os.getenv('SSOREADY_ORG_NAME', 'Multi-tenant SSO Demo'),
        SSOREADY_ORG_DOMAIN=os.getenv('SSOREADY_ORG_DOMAIN', 'company1.com'),
    )
    
    # Initialize JWT and other extensions
    with app.app_context():
        try:
            # Initialize JWT
            jwt.init_app(app)
            
            # Initialize extensions and store SSO client
            init_extensions(app)
            
            # Log SSO client status
            if app.extensions.get('sso_client'):
                app.logger.info("SSO client initialized and stored successfully")
            else:
                app.logger.warning("SSO client not available in app extensions")
            
            # Initialize Permit resources synchronously
            from app.core.extensions import init_permit_resources
            
            # Run the initialization
            init_permit_resources()
            
            logger.info("All extensions initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize extensions: {str(e)}", exc_info=True)
            raise
    
    # JWT error handlers
    @jwt.unauthorized_loader
    def custom_unauthorized_response(_err):
        return jsonify({
            'msg': 'Missing or invalid token',
            'error': 'missing_or_invalid_token'
        }), 401
        
    @jwt.invalid_token_loader
    def custom_invalid_token_response(_err):
        return jsonify({
            'msg': 'Invalid token',
            'error': 'invalid_token'
        }), 401
        
    @jwt.expired_token_loader
    def custom_expired_token_response(jwt_header, jwt_payload):
        return jsonify({
            'msg': 'Token has expired',
            'error': 'token_expired'
        }), 401
    
    # Make config available in templates
    @app.context_processor
    def inject_config():
        return dict(app_config=app_config)
    
    # Register blueprints
    from app.main.routes import main_bp
    from app.auth.routes import auth_bp
    from app.admin.routes import admin_bp
    from app.tenant.routes import tenant_bp
    
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp, url_prefix='/api/admin')
    app.register_blueprint(tenant_bp, url_prefix='/api/tenant')
    
    # Error handlers
    @app.errorhandler(401)
    def unauthorized_error(error):
        if request.path.startswith('/api/'):
            return jsonify({"error": "Unauthorized"}), 401
        return redirect(url_for('auth.login'))
    
    @app.errorhandler(403)
    def forbidden_error(error):
        if request.path.startswith('/api/'):
            return jsonify({"error": "Forbidden"}), 403
        return render_template('errors/403.html'), 403
    
    @app.errorhandler(404)
    def not_found_error(error):
        if request.path.startswith('/api/'):
            return jsonify({"error": "Not found"}), 404
        return render_template('errors/404.html'), 404
    
    return app
