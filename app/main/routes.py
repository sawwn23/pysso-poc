from flask import Blueprint, render_template, session, redirect, url_for, request, current_app
from flask_login import login_required, current_user
from flask_jwt_extended import jwt_required, get_jwt, verify_jwt_in_request
import logging
from app.config.config import Config

main_bp = Blueprint('main', __name__)
logger = logging.getLogger(__name__)

@main_bp.route('/')
def home():
    """Home page route."""
    try:
        # Try to get JWT claims
        verify_jwt_in_request(optional=True)
        claims = get_jwt()
        
        # If no claims, user is not authenticated
        if not claims:
            logger.info("User not authenticated, redirecting to login")
            return redirect(url_for('auth.login'))
            
        tenant_id = claims.get('tenant_id')
        if not tenant_id:
            logger.error("No tenant_id in JWT claims")
            return redirect(url_for('auth.login'))
        
        # Get organization info from config
        org_config = Config.get_organization(tenant_id)
        if not org_config:
            logger.error(f"No organization config found for tenant: {tenant_id}")
            return redirect(url_for('auth.login'))
            
        user_info = {
            'email': claims.get('email'),
            'name': claims.get('name'),
            'tenant_id': tenant_id,
            'org_id': org_config['organization_id'],
            'roles': claims.get('roles', ['user'])
        }
        return render_template('home.html', user_info=user_info)
    except Exception as e:
        logger.info(f"User not authenticated, redirecting to login: {str(e)}")
        return redirect(url_for('auth.login'))

@main_bp.route('/logout')
@login_required
def logout():
    """Root-level logout route that redirects to auth blueprint's logout."""
    return redirect(url_for('auth.logout'))

@main_bp.route('/callback')
def callback():
    """Redirect callback to auth blueprint"""
    return redirect(url_for('auth.callback', **request.args))
