"""
Setup functions for dependency injection based Keycloak authentication.
"""

import logging
from collections.abc import Callable
from typing import Any, Optional

from fastapi import Depends, FastAPI
from fastapi.security import OpenIdConnect
from fastapi_keycloak_middleware.dependency_factory import KeycloakDependencyFactory
from fastapi_keycloak_middleware.schemas.exception_response import ExceptionResponse
from fastapi_keycloak_middleware.schemas.keycloak_configuration import (
    KeycloakConfiguration,
)
from fastapi_keycloak_middleware.schemas.validation_strategy import (
    ValidationConfig,
    ValidationStrategy,
)

log = logging.getLogger(__name__)


def setup_keycloak_di(
    app: FastAPI,
    keycloak_configuration: KeycloakConfiguration,
    validation_config: Optional[ValidationConfig] = None,
    user_mapper: Optional[Callable[[dict[str, Any]], Any]] = None,
    scope_mapper: Optional[Callable[[list[str]], list[str]]] = None,
    add_exception_response: bool = True,
    add_swagger_auth: bool = True,
    swagger_openId_base_url: Optional[str] = None,
    swagger_auth_scopes: Optional[list[str]] = None,
    swagger_auth_pkce: bool = True,
    swagger_scheme_name: str = "keycloak-openid",
    add_metrics_endpoint: bool = False,
    metrics_endpoint_path: str = "/auth/metrics",
    require_admin_for_metrics: bool = True,
) -> KeycloakDependencyFactory:
    """
    Setup dependency injection based Keycloak authentication for FastAPI.

    This function provides a DI-first approach to Keycloak integration, offering
    more flexibility than the traditional middleware approach.

    :param app: The FastAPI app instance
    :param keycloak_configuration: Keycloak configuration object
    :param validation_config: Validation strategy configuration
    :param user_mapper: Custom async function for user mapping
    :param scope_mapper: Custom async function for scope mapping
    :param add_exception_response: Whether to add 401/403 exception responses
    :param add_swagger_auth: Whether to add OpenID Connect to Swagger
    :param swagger_openId_base_url: Base URL for OpenID Connect in Swagger
    :param swagger_auth_scopes: Scopes for Swagger UI authentication
    :param swagger_auth_pkce: Whether to use PKCE in Swagger
    :param swagger_scheme_name: Name of the OpenAPI security scheme
    :param add_metrics_endpoint: Whether to add metrics endpoint
    :param metrics_endpoint_path: Path for metrics endpoint
    :param require_admin_for_metrics: Whether metrics require admin access
    :return: KeycloakDependencyFactory instance
    """

    # Create dependency factory
    dependency_factory = KeycloakDependencyFactory(
        keycloak_configuration=keycloak_configuration,
        validation_config=validation_config,
        user_mapper=user_mapper,
        scope_mapper=scope_mapper,
    )

    # Add exception responses if requested
    if add_exception_response:
        router = app.router if isinstance(app, FastAPI) else app
        if 401 not in router.responses:
            log.debug("Adding 401 exception response")
            router.responses[401] = {
                "description": "Unauthorized",
                "model": ExceptionResponse,
            }
        else:
            log.warning(
                "DI setup is configured to add 401 exception response but it already exists"
            )

        if 403 not in router.responses:
            log.debug("Adding 403 exception response")
            router.responses[403] = {
                "description": "Forbidden",
                "model": ExceptionResponse,
            }
        else:
            log.warning(
                "DI setup is configured to add 403 exception response but it already exists"
            )
    else:
        log.debug("Skipping adding exception responses")

    # Add OpenAPI schema for Swagger
    if add_swagger_auth:
        suffix = ".well-known/openid-configuration"
        openId_base_url = swagger_openId_base_url or keycloak_configuration.url
        security_scheme = OpenIdConnect(
            openIdConnectUrl=f"{openId_base_url}/realms/{keycloak_configuration.realm}/{suffix}",
            scheme_name=swagger_scheme_name,
            auto_error=False,
        )
        client_id = (
            keycloak_configuration.swagger_client_id
            if keycloak_configuration.swagger_client_id
            else keycloak_configuration.client_id
        )
        scopes = swagger_auth_scopes if swagger_auth_scopes else ["openid", "profile"]
        swagger_ui_init_oauth = {
            "clientId": client_id,
            "scopes": scopes,
            "appName": app.title,
            "usePkceWithAuthorizationCodeGrant": swagger_auth_pkce,
        }
        app.swagger_ui_init_oauth = swagger_ui_init_oauth

        # Note: We don't add global dependency here - that's the whole point of DI approach
        # Users can add dependencies selectively to routers or endpoints
        log.info("Swagger OpenID Connect configured for manual dependency injection")

    # Add metrics endpoint if requested
    if add_metrics_endpoint:
        if require_admin_for_metrics:
            metrics_dependency = dependency_factory.create_admin_dependency()
        else:
            metrics_dependency = dependency_factory.create_auth_dependency()

        @app.get(
            metrics_endpoint_path,
            dependencies=[Depends(metrics_dependency)],
            tags=["Authentication"],
            summary="Get authentication metrics",
            response_model=dict,
        )
        async def get_auth_metrics():
            """Get current authentication metrics."""
            return dependency_factory.get_metrics().model_dump()

        log.info(f"Added authentication metrics endpoint at {metrics_endpoint_path}")

    log.info(
        f"Keycloak DI setup completed with strategy: {dependency_factory.validation_config.strategy}"
    )

    return dependency_factory


def create_global_auth_dependency(
    dependency_factory: KeycloakDependencyFactory,
    strategy: Optional[ValidationStrategy] = None,
    require_roles: Optional[list[str]] = None,
    require_scopes: Optional[list[str]] = None,
) -> Callable:
    """
    Create a global authentication dependency for use with app.include_router.

    This is a convenience function for applying authentication globally to all routes
    in a router, maintaining the DI-first approach while providing easy global application.

    Example:
        auth_dependency = create_global_auth_dependency(
            dependency_factory,
            require_roles=["user"]
        )
        app.include_router(api_router, dependencies=[Depends(auth_dependency)])

    :param dependency_factory: The KeycloakDependencyFactory instance
    :param strategy: Override validation strategy
    :param require_roles: List of required roles
    :param require_scopes: List of required scopes
    :return: Authentication dependency function
    """
    return dependency_factory.create_auth_dependency(
        strategy=strategy,
        require_roles=require_roles,
        require_scopes=require_scopes,
    )


def create_role_based_dependencies(
    dependency_factory: KeycloakDependencyFactory,
    roles_config: dict[str, list[str]],
    strategy: Optional[ValidationStrategy] = None,
) -> dict[str, Callable]:
    """
    Create multiple role-based dependencies at once.

    Example:
        dependencies = create_role_based_dependencies(
            dependency_factory,
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

    :param dependency_factory: The KeycloakDependencyFactory instance
    :param roles_config: Dict mapping dependency names to required roles
    :param strategy: Override validation strategy
    :return: Dict of dependency name to dependency function
    """
    dependencies = {}

    for dep_name, required_roles in roles_config.items():
        dependencies[dep_name] = dependency_factory.create_auth_dependency(
            strategy=strategy,
            require_roles=required_roles,
            require_all_roles=False,  # Any of the roles is sufficient
        )

    return dependencies
