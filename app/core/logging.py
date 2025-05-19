import logging

def setup_logging(app):
    """Configure application logging"""
    if app.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
        
    # Add custom formatters and handlers here if needed
    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
    )
    
    # Example: Add file handler for production
    if not app.debug:
        file_handler = logging.FileHandler('app.log')
        file_handler.setFormatter(formatter)
        app.logger.addHandler(file_handler)
