"""
Enhanced Keycloak backend with additional methods for dependency injection support.
"""

import logging
from typing import Any, Dict, List, Optional

import keycloak
from fastapi_keycloak_middleware.fast_api_user import FastApiUser
from fastapi_keycloak_middleware.keycloak_backend import KeycloakBackend
from fastapi_keycloak_middleware.schemas.keycloak_configuration import (
    KeycloakConfiguration,
)
from starlette.authentication import AuthenticationError

logger = logging.getLogger(__name__)


class EnhancedKeycloakBackend(KeycloakBackend):
    """
    Enhanced Keycloak backend with additional methods for dependency injection support.
    """

    def __init__(self, keycloak_configuration: KeycloakConfiguration):
        super().__init__(keycloak_configuration, user_mapper=None)

    async def get_userinfo(self, token: str) -> Dict[str, Any]:
        """
        Get user information from token using local JWT validation.

        :param token: JWT access token
        :return: Dictionary containing user claims
        :raises AuthenticationError: If token validation fails
        """
        try:
            if self.keycloak_configuration.use_introspection_endpoint:
                # If introspection is configured as default, use it
                return await self.introspect_token(token)

            # Use local JWT validation
            if not hasattr(self, "public_key"):
                self.public_key = self._get_public_key()

            token_info = await self.keycloak_openid.a_decode_token(
                token,
                self.keycloak_configuration.validate_token,
                **self.keycloak_configuration.validation_options,
                key=self.public_key,
            )

            return token_info

        except keycloak.exceptions.KeycloakGetError as exc:
            logger.error(f"Failed to get user info: {exc.error_message}")
            raise AuthenticationError("Invalid token") from exc
        except Exception as exc:
            logger.error(f"Token validation failed: {exc}")
            raise AuthenticationError("Token validation failed") from exc

    async def introspect_token(self, token: str) -> Dict[str, Any]:
        """
        Introspect token using Keycloak introspection endpoint.

        :param token: JWT access token
        :return: Dictionary containing token information
        :raises AuthenticationError: If introspection fails or token is invalid
        """
        try:
            token_info = await self.keycloak_openid.a_introspect(token)

            if not token_info.get("active", False):
                raise AuthenticationError("Token is not active")

            return token_info

        except keycloak.exceptions.KeycloakPostError as exc:
            logger.error(f"Token introspection failed: {exc.error_message}")
            raise AuthenticationError("Token introspection failed") from exc
        except Exception as exc:
            logger.error(f"Introspection error: {exc}")
            raise AuthenticationError("Introspection failed") from exc

    async def validate_token_scopes(self, token: str, required_scopes: List[str]) -> bool:
        """
        Validate that token contains required scopes.

        :param token: JWT access token
        :param required_scopes: List of required scopes
        :return: True if all scopes are present
        """
        try:
            userinfo = await self.get_userinfo(token)
            token_scopes = userinfo.get("scope", "").split() if userinfo.get("scope") else []

            return all(scope in token_scopes for scope in required_scopes)
        except Exception:
            return False

    async def get_token_roles(self, token: str) -> List[str]:
        """
        Extract roles from token.

        :param token: JWT access token
        :return: List of user roles
        """
        try:
            userinfo = await self.get_userinfo(token)

            # Try different places where roles might be stored
            roles = []

            # Realm roles
            if "realm_access" in userinfo and "roles" in userinfo["realm_access"]:
                roles.extend(userinfo["realm_access"]["roles"])

            # Resource/client roles
            if "resource_access" in userinfo:
                for client, client_data in userinfo["resource_access"].items():
                    if "roles" in client_data:
                        roles.extend([f"{client}:{role}" for role in client_data["roles"]])

            # Direct roles claim
            if "roles" in userinfo:
                if isinstance(userinfo["roles"], list):
                    roles.extend(userinfo["roles"])
                elif isinstance(userinfo["roles"], str):
                    roles.append(userinfo["roles"])

            return list(set(roles))  # Remove duplicates

        except Exception as exc:
            logger.warning(f"Failed to extract roles from token: {exc}")
            return []


class EnhancedFastApiUser(FastApiUser):
    """
    Enhanced FastApiUser with additional properties for roles and scopes.
    """

    def __init__(
        self,
        first_name: str = "",
        last_name: str = "",
        user_id: str = "",
        email: str = "",
        username: str = "",
        roles: Optional[List[str]] = None,
        scopes: Optional[List[str]] = None,
        **kwargs,
    ):
        super().__init__(first_name, last_name, user_id)
        self.email = email
        self.username = username
        self.roles = roles or []
        self.scopes = scopes or []

        # Store any additional claims
        for key, value in kwargs.items():
            setattr(self, key, value)

    @classmethod
    def from_userinfo(
        cls, userinfo: Dict[str, Any], claims: Optional[List[str]] = None
    ) -> "EnhancedFastApiUser":
        """
        Create EnhancedFastApiUser from userinfo dictionary.

        :param userinfo: Dictionary containing user claims
        :param claims: List of claims to extract (optional)
        :return: EnhancedFastApiUser instance
        """
        # Extract standard claims
        first_name = userinfo.get("given_name", userinfo.get("first_name", ""))
        last_name = userinfo.get("family_name", userinfo.get("last_name", ""))
        user_id = userinfo.get("sub", userinfo.get("user_id", userinfo.get("id", "")))
        email = userinfo.get("email", "")
        username = userinfo.get("preferred_username", userinfo.get("username", ""))

        # Extract roles
        roles = []
        if "realm_access" in userinfo and "roles" in userinfo["realm_access"]:
            roles.extend(userinfo["realm_access"]["roles"])

        if "resource_access" in userinfo:
            for client, client_data in userinfo["resource_access"].items():
                if "roles" in client_data:
                    roles.extend([f"{client}:{role}" for role in client_data["roles"]])

        if "roles" in userinfo:
            if isinstance(userinfo["roles"], list):
                roles.extend(userinfo["roles"])
            elif isinstance(userinfo["roles"], str):
                roles.append(userinfo["roles"])

        # Extract scopes
        scopes = []
        if "scope" in userinfo:
            if isinstance(userinfo["scope"], str):
                scopes = userinfo["scope"].split()
            elif isinstance(userinfo["scope"], list):
                scopes = userinfo["scope"]

        # Extract additional claims if specified
        extra_claims = {}
        if claims:
            for claim in claims:
                if claim in userinfo and claim not in [
                    "given_name",
                    "family_name",
                    "sub",
                    "email",
                    "preferred_username",
                    "realm_access",
                    "resource_access",
                    "roles",
                    "scope",
                ]:
                    extra_claims[claim] = userinfo[claim]

        return cls(
            first_name=first_name,
            last_name=last_name,
            user_id=user_id,
            email=email,
            username=username,
            roles=list(set(roles)),  # Remove duplicates
            scopes=scopes,
            **extra_claims,
        )

    def has_role(self, role: str) -> bool:
        """Check if user has a specific role."""
        return role in self.roles

    def has_any_role(self, roles: List[str]) -> bool:
        """Check if user has any of the specified roles."""
        return any(role in self.roles for role in roles)

    def has_all_roles(self, roles: List[str]) -> bool:
        """Check if user has all of the specified roles."""
        return all(role in self.roles for role in roles)

    def has_scope(self, scope: str) -> bool:
        """Check if user has a specific scope."""
        return scope in self.scopes

    def has_any_scope(self, scopes: List[str]) -> bool:
        """Check if user has any of the specified scopes."""
        return any(scope in self.scopes for scope in scopes)

    def has_all_scopes(self, scopes: List[str]) -> bool:
        """Check if user has all of the specified scopes."""
        return all(scope in self.scopes for scope in scopes)
