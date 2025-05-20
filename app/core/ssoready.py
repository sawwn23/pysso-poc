import httpx
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

class SSOReadyClient:
    """Client for interacting with SSOReady API."""
    
    def __init__(self, api_key: str, organization_id: str, base_url: str = "https://api.ssoready.com"):
        """Initialize SSOReady client.
        
        Args:
            api_key: SSOReady API key
            organization_id: Organization ID
            base_url: Base URL for SSOReady API
        """
        self.api_key = api_key
        self.organization_id = organization_id
        self.base_url = base_url
        self.client = httpx.Client(
            base_url=base_url,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
        )
        
    def redeem_saml_code(self, saml_access_code: str) -> Dict[str, Any]:
        """Redeem SAML access code for user information.
        
        Args:
            saml_access_code: SAML access code from SSOReady
            
        Returns:
            Dict containing user information
        """
        try:
            response = self.client.post(
                "/v1/saml/redeem",
                json={
                    "saml_access_code": saml_access_code,
                    "organization_id": self.organization_id
                }
            )
            response.raise_for_status()
            return response.json()
            
        except httpx.HTTPError as e:
            logger.error(f"Error redeeming SAML code: {str(e)}")
            raise
            
    def get_user_info(self, user_id: str) -> Dict[str, Any]:
        """Get user information from SSOReady.
        
        Args:
            user_id: User ID to fetch information for
            
        Returns:
            Dict containing user information
        """
        try:
            response = self.client.get(
                f"/v1/users/{user_id}",
                params={"organization_id": self.organization_id}
            )
            response.raise_for_status()
            return response.json()
            
        except httpx.HTTPError as e:
            logger.error(f"Error fetching user info: {str(e)}")
            raise 