"""
This module contains a base user implementation

It is mainly used if the user does not provide a custom function to retrieve
the user based on the token claims
"""

import typing
from uuid import UUID

from starlette.authentication import BaseUser


class FastApiUser(BaseUser):
    """Sample API User that gives basic functionality"""

    def __init__(self, first_name: str, last_name: str, user_id: typing.Any):
        """
        FastAPIUser Constructor
        """
        self.first_name = first_name
        self.last_name = last_name
        self.user_id = user_id

    @property
    def is_authenticated(self) -> bool:
        """
        Checks if the user is authenticated. This method essentially does nothing,
        but it could implement session logic for example.
        """
        return True

    @property
    def display_name(self) -> str:
        """Display name of the user"""
        return f"{self.first_name} {self.last_name}"

    @property
    def identity(self) -> str:
        """Identification attribute of the user"""
        return self.user_id


class EnhancedFastApiUser(FastApiUser):
    """
    Enhanced FastApiUser with additional properties for roles and scopes.
    """

    def __init__(
        self,
        first_name: str = "",
        last_name: str = "",
        user_id: typing.Any = None,
        email: str = "",
        username: str = "",
        roles: list[str] | None = None,
        scopes: list[str] | None = None,
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
        cls, userinfo: dict[str, typing.Any], claims: list[str] | None = None
    ) -> "EnhancedFastApiUser":
        """
        Create EnhancedFastApiUser from userinfo dictionary.
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

    def has_any_role(self, roles: list[str]) -> bool:
        """Check if user has any of the specified roles."""
        return any(role in self.roles for role in roles)

    def has_all_roles(self, roles: list[str]) -> bool:
        """Check if user has all of the specified roles."""
        return all(role in self.roles for role in roles)

    def has_scope(self, scope: str) -> bool:
        """Check if user has a specific scope."""
        return scope in self.scopes

    def has_any_scope(self, scopes: list[str]) -> bool:
        """Check if user has any of the specified scopes."""
        return any(scope in self.scopes for scope in scopes)

    def has_all_scopes(self, scopes: list[str]) -> bool:
        """Check if user has all of the specified scopes."""
        return all(scope in self.scopes for scope in scopes)

    @property
    def user_uuid(self) -> UUID | None:
        """UUID representation for database comparison"""
        match self.user_id:
            case None:
                return None
            case UUID() as uuid_val:
                return uuid_val
            case str() as str_val:
                try:
                    return UUID(str_val)
                except ValueError:
                    return None
            case _:
                return None

    def matches_user_id(self, other_user_id: typing.Any) -> bool:
        """Check if this user matches the given user ID (supports UUID and string comparison)."""
        if other_user_id is None or self.user_id is None:
            return other_user_id == self.user_id
        # try UUID comparison first if both can be converted to UUID
        self_uuid = self.user_uuid
        if self_uuid:
            try:
                other_uuid = UUID(str(other_user_id)) if not isinstance(other_user_id, UUID) else other_user_id
                return self_uuid == other_uuid
            except ValueError:
                pass
        # fallback to string comparison
        return str(self.user_id) == str(other_user_id)
