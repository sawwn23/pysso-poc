# filepath: /home/sawwinnaung/CascadeProjects/python-ssoready-app/app/core/extensions.py
import os
from ssoready.client import SSOReady
from flask import current_app
import asyncio
from app.config.config import Config

def run_sync(coro):
    """Run an async coroutine synchronously"""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    return loop.run_until_complete(coro)

# Global instances
sso_client = None

def init_extensions(app):
    """Initialize Flask extensions"""
    global sso_client
    
    try:
        # Initialize SSOReady client if API key is configured
        sso_api_key = app.config.get('SSOREADY_API_KEY') or os.getenv('SSOREADY_API_KEY')
        
        app.logger.info(f"SSO Configuration - API Key: {'Set' if sso_api_key else 'Not set'}")
        
        if not sso_api_key:
            app.logger.warning("SSO features disabled. Missing required configuration: SSOREADY_API_KEY")
            sso_client = None
            return
            
        try:
            sso_base_url = app.config.get('SSOREADY_BASE_URL') or os.getenv('SSOREADY_BASE_URL', 'https://api.ssoready.com')
            app.logger.info(f"Initializing SSOReady client with base URL: {sso_base_url}")
            
            # Initialize SSOReady client with API key
            sso_client = SSOReady(
                api_key=sso_api_key
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