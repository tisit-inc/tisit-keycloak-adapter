"""
Middleware for FastAPI that supports authenticating users against Keycloak
"""

__version__ = "1.3.0"

import logging

import fastapi_keycloak_middleware.dependency_factory as deps_module
from fastapi_keycloak_middleware.decorators.require_permission import require_permission
from fastapi_keycloak_middleware.decorators.strip_request import strip_request
from fastapi_keycloak_middleware.dependencies.check_permission import CheckPermissions
from fastapi_keycloak_middleware.dependencies.get_auth import get_auth
from fastapi_keycloak_middleware.dependencies.get_authorization_result import (
    get_authorization_result,
)
from fastapi_keycloak_middleware.dependencies.get_user import get_user
from fastapi_keycloak_middleware.fast_api_user import FastApiUser
from fastapi_keycloak_middleware.middleware import KeycloakMiddleware
from fastapi_keycloak_middleware.schemas.authorization_methods import (
    AuthorizationMethod,
)
from fastapi_keycloak_middleware.schemas.authorization_result import AuthorizationResult
from fastapi_keycloak_middleware.schemas.keycloak_configuration import (
    KeycloakConfiguration,
)
from fastapi_keycloak_middleware.schemas.match_strategy import MatchStrategy

# Global authentication approach - middleware
from fastapi_keycloak_middleware.setup import setup_keycloak_middleware

# Selective authentication approach - DI dependencies
from fastapi_keycloak_middleware.setup_keycloak import (
    create_keycloak_singleton,
    setup_keycloak,
    setup_swagger_only,
)

create_auth_dependency = deps_module.create_auth_dependency
create_optional_auth_dependency = deps_module.create_optional_auth_dependency
create_admin_dependency = deps_module.create_admin_dependency
create_role_based_dependencies = deps_module.create_role_based_dependencies
create_global_auth_dependency = deps_module.create_global_auth_dependency
get_keycloak_backend_dependency = deps_module.get_keycloak_backend_dependency

from fastapi_keycloak_middleware.fast_api_user import EnhancedFastApiUser
from fastapi_keycloak_middleware.keycloak_backend import KeycloakBackend
from fastapi_keycloak_middleware.schemas.validation_strategy import (
    AuthMetrics,
    ValidationConfig,
    ValidationStrategy,
)

logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    # Global authentication approach - middleware
    "AuthorizationResult",
    "KeycloakMiddleware", 
    "KeycloakConfiguration",
    "AuthorizationMethod",
    "MatchStrategy",
    "FastApiUser",
    "CheckPermissions",
    "get_auth",
    "get_user", 
    "get_authorization_result",
    "require_permission",
    "setup_keycloak_middleware",
    "strip_request",
    
    # Selective authentication approach - DI dependencies
    "setup_keycloak",
    "create_keycloak_singleton",
    "setup_swagger_only",
    "create_auth_dependency",
    "create_optional_auth_dependency", 
    "create_admin_dependency",
    "create_role_based_dependencies",
    "create_global_auth_dependency",
    "get_keycloak_backend_dependency",
    "KeycloakBackend",
    "EnhancedFastApiUser",
    "ValidationStrategy",
    "ValidationConfig", 
    "AuthMetrics",
]
