"""
Setup functions for the new simplified Keycloak DI-first architecture.
"""

import logging
from collections.abc import Callable
from typing import Any, Optional

from fastapi import Depends, FastAPI
from fastapi.security import OpenIdConnect

from tisit_keycloak_adapter.dependencies import (
    create_admin_dependency,
    create_auth_dependency,
    get_keycloak_backend_dependency,
)
from tisit_keycloak_adapter.keycloak_backend import KeycloakBackend
from tisit_keycloak_adapter.schemas.exception_response import ExceptionResponse
from tisit_keycloak_adapter.schemas.keycloak_configuration import KeycloakConfiguration
from tisit_keycloak_adapter.schemas.validation_strategy import (
    ValidationConfig,
)

log = logging.getLogger(__name__)


def setup_keycloak(
    app: FastAPI,
    keycloak_configuration: KeycloakConfiguration,
    validation_config: Optional[ValidationConfig] = None,
    user_mapper: Optional[Callable[[dict[str, Any]], Any]] = None,
    add_exception_response: bool = True,
    add_swagger_auth: bool = True,
    swagger_openid_base_url: Optional[str] = None,
    swagger_auth_scopes: Optional[list[str]] = None,
    swagger_auth_pkce: bool = True,
    swagger_scheme_name: str = "keycloak-openid",
    add_metrics_endpoint: bool = False,
    metrics_endpoint_path: str = "/auth/metrics",
    require_admin_for_metrics: bool = True,
) -> KeycloakBackend:
    """
    Setup Keycloak authentication for FastAPI with DI-first architecture.

    This function creates a singleton KeycloakBackend instance and optionally configures
    FastAPI for Swagger integration and metrics endpoints.

    :param app: The FastAPI app instance
    :param keycloak_configuration: Keycloak configuration object
    :param validation_config: Validation strategy configuration
    :param user_mapper: Custom async function for user mapping
    :param add_exception_response: Whether to add 401/403 exception responses
    :param add_swagger_auth: Whether to add OpenID Connect to Swagger
    :param swagger_openid_base_url: Base URL for OpenID Connect in Swagger
    :param swagger_auth_scopes: Scopes for Swagger UI authentication
    :param swagger_auth_pkce: Whether to use PKCE in Swagger
    :param swagger_scheme_name: Name of the OpenAPI security scheme
    :param add_metrics_endpoint: Whether to add metrics endpoint
    :param metrics_endpoint_path: Path for metrics endpoint
    :param require_admin_for_metrics: Whether metrics require admin access
    :return: KeycloakBackend instance (singleton)
    """

    # Create the singleton backend
    backend = KeycloakBackend(
        keycloak_configuration=keycloak_configuration,
        user_mapper=user_mapper,
        validation_config=validation_config,
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
            log.warning("Setup is configured to add 401 exception response but it already exists")

        if 403 not in router.responses:
            log.debug("Adding 403 exception response")
            router.responses[403] = {
                "description": "Forbidden",
                "model": ExceptionResponse,
            }
        else:
            log.warning("Setup is configured to add 403 exception response but it already exists")
    else:
        log.debug("Skipping adding exception responses")

    # Add OpenAPI schema for Swagger
    if add_swagger_auth:
        suffix = ".well-known/openid-configuration"
        openid_base_url = swagger_openid_base_url or keycloak_configuration.url
        OpenIdConnect(
            openIdConnectUrl=f"{openid_base_url}/realms/{keycloak_configuration.realm}/{suffix}",
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

        log.info("Swagger OpenID Connect configured for DI-based authentication")

    # Add metrics endpoint if requested
    if add_metrics_endpoint:
        backend_dep = get_keycloak_backend_dependency(backend)

        if require_admin_for_metrics:
            metrics_dependency = create_admin_dependency(backend)
        else:
            metrics_dependency = create_auth_dependency(backend)

        @app.get(
            metrics_endpoint_path,
            dependencies=[Depends(metrics_dependency)],
            tags=["Authentication"],
            summary="Get authentication metrics",
            response_model=dict,
        )
        async def get_auth_metrics(backend: KeycloakBackend = Depends(backend_dep)):
            """Get current authentication metrics."""
            return backend.get_metrics().model_dump()

        log.info(f"Added authentication metrics endpoint at {metrics_endpoint_path}")

    validation_strategy = backend.validation_config.strategy
    log.info(f"Keycloak setup completed with strategy: {validation_strategy}")

    return backend


# Convenience functions for common patterns
def create_keycloak_singleton(
    keycloak_configuration: KeycloakConfiguration,
    validation_config: Optional[ValidationConfig] = None,
    user_mapper: Optional[Callable[[dict[str, Any]], Any]] = None,
) -> KeycloakBackend:
    """
    Create a KeycloakBackend singleton without FastAPI setup.

    Use this when you want to create the backend instance separately
    from FastAPI configuration.

    :param keycloak_configuration: Keycloak configuration
    :param validation_config: Validation strategy configuration
    :param user_mapper: Custom user mapping function
    :return: KeycloakBackend instance
    """
    return KeycloakBackend(
        keycloak_configuration=keycloak_configuration,
        user_mapper=user_mapper,
        validation_config=validation_config,
    )


def setup_swagger_only(
    app: FastAPI,
    keycloak_configuration: KeycloakConfiguration,
    swagger_openid_base_url: Optional[str] = None,
    swagger_auth_scopes: Optional[list[str]] = None,
    swagger_auth_pkce: bool = True,
    swagger_scheme_name: str = "keycloak-openid",
) -> None:
    """
    Setup only Swagger OpenID Connect configuration without creating a backend.

    Use this when you already have a backend instance and only want to configure Swagger.

    :param app: FastAPI app instance
    :param keycloak_configuration: Keycloak configuration
    :param swagger_openid_base_url: Base URL for OpenID Connect
    :param swagger_auth_scopes: Authentication scopes
    :param swagger_auth_pkce: Whether to use PKCE
    :param swagger_scheme_name: Security scheme name
    """
    suffix = ".well-known/openid-configuration"
    openid_base_url = swagger_openid_base_url or keycloak_configuration.url
    OpenIdConnect(
        openIdConnectUrl=f"{openid_base_url}/realms/{keycloak_configuration.realm}/{suffix}",
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

    log.info("Swagger OpenID Connect configured")
