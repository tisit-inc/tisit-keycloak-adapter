"""
Setup functions for the new simplified Keycloak DI-first architecture.
"""

import logging
from collections.abc import Callable
from typing import Any, Optional

from fastapi import Depends, FastAPI
from fastapi.security import OAuth2AuthorizationCodeBearer, OpenIdConnect

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

def _normalize_base_url(url: str) -> str:
    """Ensure no trailing slash to avoid double slashes when composing URLs."""
    return url.rstrip("/")


def _compose_urls(base_url: str, realm: str) -> dict[str, str]:
    base = _normalize_base_url(base_url)
    realm_path = f"{base}/realms/{realm}"
    return {
        "auth": f"{realm_path}/protocol/openid-connect/auth",
        "token": f"{realm_path}/protocol/openid-connect/token",
        "discovery": f"{realm_path}/.well-known/openid-configuration",
    }


def _configure_swagger_ui_init(
    app: FastAPI,
    client_id: str,
    scopes: list[str],
    app_title: str,
    pkce: bool,
) -> None:
    app.swagger_ui_init_oauth = {
        "clientId": client_id,
        "scopes": scopes,
        "appName": app_title,
        "usePkceWithAuthorizationCodeGrant": pkce,
    }


def _attach_security_scheme(
    app: FastAPI,
    mode: str,
    urls: dict[str, str],
    scheme_name: str,
    scopes: list[str],
) -> None:
    if mode == "oauth2":
        oauth2_scheme = OAuth2AuthorizationCodeBearer(
            authorizationUrl=urls["auth"],
            tokenUrl=urls["token"],
            scheme_name=scheme_name,
            scopes={scope: scope for scope in scopes},
            auto_error=False,
        )
        app.router.dependencies.append(Depends(oauth2_scheme))
    else:
        security_scheme = OpenIdConnect(
            openIdConnectUrl=urls["discovery"],
            scheme_name=scheme_name,
            auto_error=False,
        )
        app.router.dependencies.append(Depends(security_scheme))


def setup_keycloak(
    app: FastAPI,
    keycloak_configuration: KeycloakConfiguration,
    validation_config: ValidationConfig | None = None,
    user_mapper: Callable[[dict[str, Any]], Any] | None = None,
    add_exception_response: bool = True,
    add_swagger_auth: bool = True,
    swagger_openid_base_url: str | None = None,
    swagger_auth_scopes: list[str] | None = None,
    swagger_auth_pkce: bool = True,
    swagger_scheme_name: str = "keycloak-openid",
    swagger_security_type: str = "openid",  # "openid" (default) or "oauth2"
    swagger_oauth2_flows: list[str] | None = None,  # e.g. ["authorization_code"]
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
        openid_base_url = _normalize_base_url(
            swagger_openid_base_url or keycloak_configuration.url
        )
        client_id = (
            keycloak_configuration.swagger_client_id
            if keycloak_configuration.swagger_client_id
            else keycloak_configuration.client_id
        )
        scopes_list = swagger_auth_scopes if swagger_auth_scopes else ["openid", "profile"]
        _configure_swagger_ui_init(app, client_id, scopes_list, app.title, swagger_auth_pkce)
        urls = _compose_urls(openid_base_url, keycloak_configuration.realm)
        requested_oauth2_flows = swagger_oauth2_flows or ["authorization_code"]
        mode = (
            "oauth2"
            if (swagger_security_type == "oauth2" and requested_oauth2_flows)
            else "openid"
        )
        _attach_security_scheme(app, mode, urls, swagger_scheme_name, scopes_list)
        log.info(
            "Swagger %s configured for DI-based authentication",
            "OAuth2 (authorization_code)" if mode == "oauth2" else "OpenID Connect",
        )

    # Add metrics endpoint if requested
    if add_metrics_endpoint:
        backend_dep = get_keycloak_backend_dependency(backend)

        if require_admin_for_metrics:
            if getattr(backend.keycloak_configuration, "enforce_admin_roles", True):
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
    validation_config: ValidationConfig | None = None,
    user_mapper: Callable[[dict[str, Any]], Any] | None = None,
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
    swagger_security_type: str = "openid",  # "openid" (default) or "oauth2"
    swagger_oauth2_flows: list[str] | None = None,  # e.g. ["authorization_code"]
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
    openid_base_url = _normalize_base_url(
        swagger_openid_base_url or keycloak_configuration.url
    )
    client_id = (
        keycloak_configuration.swagger_client_id
        if keycloak_configuration.swagger_client_id
        else keycloak_configuration.client_id
    )
    scopes_list = swagger_auth_scopes if swagger_auth_scopes else ["openid", "profile"]
    _configure_swagger_ui_init(app, client_id, scopes_list, app.title, swagger_auth_pkce)
    urls = _compose_urls(openid_base_url, keycloak_configuration.realm)
    requested_oauth2_flows = swagger_oauth2_flows or ["authorization_code"]
    mode = (
        "oauth2" if (swagger_security_type == "oauth2" and requested_oauth2_flows) else "openid"
    )
    _attach_security_scheme(app, mode, urls, swagger_scheme_name, scopes_list)
    log.info(
        "Swagger %s configured",
        "OAuth2 (authorization_code)" if mode == "oauth2" else "OpenID Connect",
    )
