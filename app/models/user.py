from flask_login import UserMixin
from datetime import datetime
import uuid
import logging

logger = logging.getLogger(__name__)

class User(UserMixin):
    """User model for authentication and authorization."""
    
    # Class-level user storage
    _users = {}
    
    def __init__(self, id, email, name, tenant_id, created_at=None, updated_at=None):
        self.id = id
        self.email = email
        self.name = name
        self.tenant_id = tenant_id
        self.created_at = created_at or datetime.utcnow()
        self.updated_at = updated_at or datetime.utcnow()
    
    @classmethod
    def create(cls, email, name, tenant_id):
        """Create a new user."""
        user = cls(
            id=str(uuid.uuid4()),
            email=email,
            name=name,
            tenant_id=tenant_id
        )
        cls._users[email] = user
        logger.info(f"Created new user: {email}")
        return user
    
    @classmethod
    def get_by_email(cls, email):
        """Get a user by email."""
        return cls._users.get(email)
    
    @classmethod
    def get_by_id(cls, user_id):
        """Get a user by ID."""
        for user in cls._users.values():
            if user.id == user_id:
                return user
        return None
    
    @classmethod
    def get_all(cls):
        """Get all users."""
        return list(cls._users.values())
    
    def get_id(self):
        """Get the user ID for Flask-Login."""
        return str(self.id)
    
    def is_authenticated(self):
        """Check if the user is authenticated."""
        return True
    
    def is_active(self):
        """Check if the user is active."""
        return True
    
    def is_anonymous(self):
        """Check if the user is anonymous."""
        return False 