import logging
import requests
from typing import Optional
from urllib.parse import urlencode

from configs import dify_config
from models.account import Account
from services.account_service import AccountService, TenantService
from events.tenant_event import tenant_was_created
from extensions.ext_database import db
from constants.languages import languages

logger = logging.getLogger(__name__)


class KeycloakAuthService:
    """Service for handling Keycloak authentication"""

    @staticmethod
    def is_keycloak_enabled() -> bool:
        """Check if Keycloak authentication is enabled and properly configured"""
        return (
            dify_config.KEYCLOAK_ENABLED
            and dify_config.KEYCLOAK_AUTH_SERVER_URL
            and dify_config.KEYCLOAK_REALM
            and dify_config.KEYCLOAK_CLIENT_ID
            and dify_config.KEYCLOAK_CLIENT_SECRET
        )

    @staticmethod
    def authenticate_with_keycloak(username: str, password: str) -> dict:
        """
        Authenticate user with Keycloak using username/password
        Returns both Keycloak tokens and user info if successful
        """
        if not KeycloakAuthService.is_keycloak_enabled():
            raise ValueError("Keycloak authentication is not properly configured")

        try:
            # Get access token from Keycloak
            # Ensure URL doesn't have /auth path for newer Keycloak versions (17+)
            base_url = dify_config.KEYCLOAK_AUTH_SERVER_URL.rstrip('/')
            if base_url.endswith('/auth'):
                base_url = base_url[:-5]  # Remove /auth suffix
            token_url = f"{base_url}/realms/{dify_config.KEYCLOAK_REALM}/protocol/openid-connect/token"
            logger.info(f"Keycloak token_url: {token_url}")
            token_data = {
                "grant_type": "password",
                "client_id": dify_config.KEYCLOAK_CLIENT_ID,
                "client_secret": dify_config.KEYCLOAK_CLIENT_SECRET,
                "username": username,
                "password": password,
                "scope": "openid profile email",
            }
            # Log sanitized data (without password)
            sanitized_data = {k: v for k, v in token_data.items() if k != 'password'}
            logger.info(f"Keycloak request data: {sanitized_data}")
            # Request token from Keycloak
            token_response = requests.post(
                token_url,
                data=urlencode(token_data),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10,
                verify=False,  # Set to True in production with proper SSL setup
            )
            logger.info(f"Keycloak token_response: {token_response}")
            if token_response.status_code == 401:
                raise ValueError("Invalid username or password")
            elif token_response.status_code == 400:
                raise ValueError("Invalid request parameters")
            elif token_response.status_code != 200:
                raise ValueError(f"Keycloak authentication failed: {token_response.text}")

            tokens = token_response.json()

            # Get user info from Keycloak
            user_info = KeycloakAuthService._get_user_info_from_token(tokens["access_token"])

            if not user_info:
                raise ValueError("Failed to retrieve user information from Keycloak")

            return {
                "tokens": tokens,
                "user_info": user_info,
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"Keycloak authentication request error: {e}")
            raise ValueError("Keycloak server is unavailable")
        except Exception as e:
            logger.error(f"Keycloak authentication error: {e}")
            raise ValueError(f"Authentication failed: {str(e)}")

    @staticmethod
    def _get_user_info_from_token(access_token: str) -> Optional[dict]:
        """
        Extract user info from Keycloak access token
        """
        try:
            # Ensure URL doesn't have /auth path for newer Keycloak versions (17+)
            base_url = dify_config.KEYCLOAK_AUTH_SERVER_URL.rstrip('/')
            if base_url.endswith('/auth'):
                base_url = base_url[:-5]  # Remove /auth suffix
            user_info_url = f"{base_url}/realms/{dify_config.KEYCLOAK_REALM}/protocol/openid-connect/userinfo"

            user_info_response = requests.get(
                user_info_url,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=10,
                verify=False,  # Set to True in production with proper SSL setup
            )

            if user_info_response.status_code != 200:
                logger.error(f"Failed to get user info: {user_info_response.text}")
                return None

            user_info = user_info_response.json()

            return {
                "id": user_info.get("sub"),
                "username": user_info.get("preferred_username"),
                "email": user_info.get("email"),
                "first_name": user_info.get("given_name"),
                "last_name": user_info.get("family_name"),
                "roles": user_info.get("realm_access", {}).get("roles", []),
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error getting user info from Keycloak: {e}")
            return None
        except Exception as e:
            logger.error(f"Error processing user info: {e}")
            return None

    @staticmethod
    def find_matching_dify_user(keycloak_user_info: dict) -> Optional[Account]:
        """
        Find a matching Dify user based on email or username
        Only matches if Keycloak email/username exactly matches Dify email
        """
        email = keycloak_user_info.get("email")
        username = keycloak_user_info.get("username")

        if not email:
            logger.warning("Keycloak user has no email address")
            return None

        # First try to match by email (primary matching criteria)
        account = db.session.query(Account).filter_by(email=email).first()

        # If no email match and username is provided, try username match
        # but only if the username looks like an email (contains @)
        if not account and username and "@" in username:
            account = db.session.query(Account).filter_by(email=username).first()

        return account

    @staticmethod
    def _create_dify_user_from_keycloak(keycloak_user_info: dict, password: str) -> Account:
        """
        Create a new Dify user account based on Keycloak user information
        """
        email = keycloak_user_info.get("email")
        first_name = keycloak_user_info.get("first_name", "")
        last_name = keycloak_user_info.get("last_name", "")
        username = keycloak_user_info.get("username", "")
        
        if not email:
            raise ValueError("Keycloak user must have an email address to create Dify account")
        
        # Create display name from available information
        if first_name and last_name:
            display_name = f"{first_name} {last_name}".strip()
        elif first_name:
            display_name = first_name
        elif username:
            display_name = username
        else:
            display_name = email.split('@')[0]  # Use email prefix as fallback
        
        try:
            # Create the account using AccountService
            account = AccountService.create_account(
                email=email,
                name=display_name,
                interface_language=languages[0],  # Use default language
                password=password,  # Store the password from Keycloak authentication
                interface_theme="light",
                is_setup=False
            )
            
            # Create a workspace for the user
            TenantService.create_owner_tenant_if_not_exist(account)
            
            logger.info(f"Successfully created Dify account for Keycloak user: {email}")
            return account
            
        except Exception as e:
            logger.error(f"Failed to create Dify account for Keycloak user {email}: {str(e)}")
            raise ValueError(f"Failed to create Dify account: {str(e)}")

    @staticmethod
    def authenticate_user(username: str, password: str) -> dict:
        """
        Main authentication method that:
        1. Authenticates with Keycloak
        2. Finds matching Dify user or creates new one
        3. Creates Dify session
        4. Returns combined response
        """
        # Authenticate with Keycloak
        keycloak_response = KeycloakAuthService.authenticate_with_keycloak(username, password)
        keycloak_user_info = keycloak_response["user_info"]

        # Find matching Dify user
        dify_user = KeycloakAuthService.find_matching_dify_user(keycloak_user_info)

        if not dify_user:
            # Create new Dify account based on Keycloak user data
            dify_user = KeycloakAuthService._create_dify_user_from_keycloak(keycloak_user_info, password)
            logger.info(f"Created new Dify account for Keycloak user: {keycloak_user_info.get('email')}")

        # Generate Dify session tokens
        token_pair = AccountService.login(account=dify_user)

        return {
            "access_token": token_pair.access_token,
            "refresh_token": token_pair.refresh_token,
            "keycloak_tokens": keycloak_response["tokens"],
            "keycloak_user": keycloak_user_info,
            "user": {
                "id": dify_user.id,
                "email": dify_user.email,
                "name": dify_user.name,
            },
        }
