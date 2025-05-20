#!/usr/bin/env python
import os
import logging
from pathlib import Path
from dotenv import load_dotenv

# Set up basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def load_environment():
    """Load environment variables from .env file if it exists"""
    env_path = Path(__file__).parent / '.env'
    if env_path.exists():
        logger.info(f"Found .env file at {env_path}")
        load_dotenv(dotenv_path=env_path, override=True)
        logger.info(f"Loaded environment variables from {env_path}")
        
        # Log important environment variables (without sensitive values)
        env_vars = [
            'FLASK_ENV', 'FLASK_APP', 'PORT',
            'SSOREADY_ORGANIZATION_ID'
        ]
        
        for var in env_vars:
            value = os.getenv(var)
            logger.info(f"{var}: {'Set' if value else 'Not set'} (Value: {value if value else 'None'})")
        
        # Log sensitive variables are set (but not their values)
        sensitive_vars = ['SSOREADY_API_KEY', 'SECRET_KEY', 'JWT_SECRET_KEY']
        for var in sensitive_vars:
            value = os.getenv(var)
            logger.info(f"{var}: {'Set' if value else 'Not set'} (Length: {len(value) if value else 0})")
    else:
        logger.warning(f"No .env file found at {env_path}. Using system environment variables.")

try:
    # Load environment variables first
    load_environment()
    
    # Import Config after loading environment variables
    from app.config.config import Config
    
    # Validate environment variables
    Config()
    
    # Import and create app after environment is validated
    from app import create_app
    
    app = create_app()
    
except Exception as e:
    logger.error(f"Failed to initialize application: {str(e)}", exc_info=True)
    raise

if __name__ == '__main__':
    try:
        # Run in debug mode if FLASK_ENV is development
        debug = os.getenv('FLASK_ENV', 'development') == 'development'
        port = int(os.getenv('PORT', 5000))
        
        logger.info(f"Starting application in {'debug' if debug else 'production'} mode on port {port}")
        logger.info(f"SSOREADY_API_KEY: {'Set' if os.getenv('SSOREADY_API_KEY') else 'Not set'}")
        
        app.run(debug=debug, host='0.0.0.0', port=port)
    except Exception as e:
        logger.error(f"Failed to start application: {str(e)}", exc_info=True)
        raise
