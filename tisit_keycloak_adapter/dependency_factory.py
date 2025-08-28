"""
Simple dependency injection functions for Keycloak authentication.
"""

from collections.abc import Callable
from typing import Optional

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.authentication import AuthenticationError

from tisit_keycloak_adapter.keycloak_backend import EnhancedFastApiUser, KeycloakBackend
from tisit_keycloak_adapter.schemas.keycloak_configuration import KeycloakConfiguration
from tisit_keycloak_adapter.schemas.validation_strategy import ValidationStrategy


def create_auth_dependency(
    backend: KeycloakBackend,
    strategy: ValidationStrategy = ValidationStrategy.JWT_LOCAL,
    require_roles: Optional[list[str]] = None,
    require_scopes: Optional[list[str]] = None,
    require_all_roles: bool = True,
    require_all_scopes: bool = True,
) -> Callable:
    """
    Create an authentication dependency with specified requirements.

    :param backend: KeycloakBackend instance
    :param strategy: Validation strategy to use
    :param require_roles: List of required roles
    :param require_scopes: List of required scopes
    :param require_all_roles: Whether all roles are required (AND) or any (OR)
    :param require_all_scopes: Whether all scopes are required (AND) or any (OR)
    :return: Authentication dependency function
    """
    security = HTTPBearer(auto_error=True)

    async def auth_dependency(
        credentials: HTTPAuthorizationCredentials = Depends(security),
    ) -> EnhancedFastApiUser:
        try:
            # Validate token using the backend
            user = await backend.validate_token_with_strategy(credentials.credentials, strategy)

            # Check role requirements
            if require_roles:
                user_roles = set(user.roles)
                required_roles = set(require_roles)

                if require_all_roles:
                    if not required_roles.issubset(user_roles):
                        missing_roles = required_roles - user_roles
                        raise HTTPException(
                            status_code=403,
                            detail=f"Missing required roles: {list(missing_roles)}",
                        )
                else:
                    if not required_roles.intersection(user_roles):
                        raise HTTPException(
                            status_code=403,
                            detail=f"None of required roles found: {require_roles}",
                        )

            # Check scope requirements
            if require_scopes:
                user_scopes = set(user.scopes)
                required_scopes = set(require_scopes)

                if require_all_scopes:
                    if not required_scopes.issubset(user_scopes):
                        missing_scopes = required_scopes - user_scopes
                        raise HTTPException(
                            status_code=403,
                            detail=f"Missing required scopes: {list(missing_scopes)}",
                        )
                else:
                    if not required_scopes.intersection(user_scopes):
                        raise HTTPException(
                            status_code=403,
                            detail=f"None of required scopes found: {require_scopes}",
                        )

            return user

        except AuthenticationError:
            raise HTTPException(status_code=401, detail="Invalid token")
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=500, detail="Authentication error")

    return auth_dependency


def create_optional_auth_dependency(
    backend: KeycloakBackend,
    strategy: ValidationStrategy = ValidationStrategy.JWT_LOCAL,
) -> Callable:
    """
    Create an optional authentication dependency.

    :param backend: KeycloakBackend instance
    :param strategy: Validation strategy to use
    :return: Optional authentication dependency function
    """
    security = HTTPBearer(auto_error=False)

    async def optional_auth_dependency(
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    ) -> Optional[EnhancedFastApiUser]:
        if not credentials or not credentials.credentials:
            return None

        try:
            return await backend.validate_token_with_strategy(credentials.credentials, strategy)
        except Exception:
            return None

    return optional_auth_dependency


def create_admin_dependency(
    backend: KeycloakBackend,
    admin_roles: Optional[list[str]] = None,
    strategy: ValidationStrategy = ValidationStrategy.JWT_WITH_FALLBACK,
) -> Callable:
    """
    Create a dependency that requires admin roles.

    :param backend: KeycloakBackend instance
    :param admin_roles: List of admin role names
    :param strategy: Validation strategy to use (default: JWT_WITH_FALLBACK for security)
    :return: Admin authentication dependency function
    """

    config: KeycloakConfiguration = backend.keycloak_configuration

    # If enforcement is disabled, just require authentication without role checks
    if not getattr(config, "enforce_admin_roles", True):
        return create_auth_dependency(
            backend=backend,
            strategy=strategy,
        )

    admin_roles = admin_roles or getattr(config, "admin_roles", ["admin", "administrator"])

    return create_auth_dependency(
        backend=backend,
        strategy=strategy,
        require_roles=admin_roles,
        require_all_roles=False,  # Any admin role is sufficient
    )


def create_role_based_dependencies(
    backend: KeycloakBackend,
    roles_config: dict[str, list[str]],
    strategy: ValidationStrategy = ValidationStrategy.JWT_LOCAL,
) -> dict[str, Callable]:
    """
    Create multiple role-based dependencies at once.

    Example:
        dependencies = create_role_based_dependencies(
            backend,
            {
                "admin": ["admin", "super_admin"],
                "user": ["user", "admin", "super_admin"],
                "moderator": ["moderator", "admin"]
            }
        )

        # Usage:
        @app.get("/admin-only", dependencies=[Depends(dependencies["admin"])])
        async def admin_endpoint():
            return {"message": "Admin only"}

    :param backend: KeycloakBackend instance
    :param roles_config: Dict mapping dependency names to required roles
    :param strategy: Validation strategy to use
    :return: Dict of dependency name to dependency function
    """
    dependencies = {}

    for dep_name, required_roles in roles_config.items():
        dependencies[dep_name] = create_auth_dependency(
            backend=backend,
            strategy=strategy,
            require_roles=required_roles,
            require_all_roles=False,  # Any of the roles is sufficient
        )

    return dependencies


def create_global_auth_dependency(
    backend: KeycloakBackend,
    strategy: ValidationStrategy = ValidationStrategy.JWT_LOCAL,
    require_roles: Optional[list[str]] = None,
    require_scopes: Optional[list[str]] = None,
) -> Callable:
    """
    Create a global authentication dependency for use with app.include_router.

    This is a convenience function for applying authentication globally to all routes
    in a router, maintaining the DI-first approach while providing easy global application.

    Example:
        auth_dependency = create_global_auth_dependency(
            backend,
            require_roles=["user"]
        )
        app.include_router(api_router, dependencies=[Depends(auth_dependency)])

    :param backend: KeycloakBackend instance
    :param strategy: Validation strategy to use
    :param require_roles: List of required roles
    :param require_scopes: List of required scopes
    :return: Authentication dependency function
    """
    return create_auth_dependency(
        backend=backend,
        strategy=strategy,
        require_roles=require_roles,
        require_scopes=require_scopes,
    )


def get_keycloak_backend_dependency(backend: KeycloakBackend) -> Callable:
    """
    Create a dependency that provides the KeycloakBackend instance.

    This allows endpoints to access the backend directly for user management operations.

    Example:
        backend_dep = get_keycloak_backend_dependency(keycloak_backend)

        @app.post("/admin/user/{user_id}/roles")
        async def assign_role(
            user_id: str,
            role: str,
            backend: KeycloakBackend = Depends(backend_dep)
        ):
            await backend.assign_role_to_user(user_id, role)
            return {"status": "role assigned"}

    :param backend: KeycloakBackend instance
    :return: Dependency function that returns the backend
    """

    async def backend_dependency() -> KeycloakBackend:
        return backend

    return backend_dependency
