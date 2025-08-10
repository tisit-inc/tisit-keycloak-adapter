"""
Middleware for FastAPI that supports authenticating users against Keycloak
"""

__version__ = "1.3.0"

import logging

import tisit_keycloak_adapter.dependency_factory as deps_module
from tisit_keycloak_adapter.decorators.require_permission import require_permission
from tisit_keycloak_adapter.decorators.strip_request import strip_request
from tisit_keycloak_adapter.dependencies.check_permission import CheckPermissions
from tisit_keycloak_adapter.dependencies.get_auth import get_auth
from tisit_keycloak_adapter.dependencies.get_authorization_result import (
    get_authorization_result,
)
from tisit_keycloak_adapter.dependencies.get_user import get_user
from tisit_keycloak_adapter.fast_api_user import EnhancedFastApiUser, FastApiUser
from tisit_keycloak_adapter.keycloak_backend import KeycloakBackend
from tisit_keycloak_adapter.middleware import KeycloakMiddleware
from tisit_keycloak_adapter.schemas.authorization_methods import (
    AuthorizationMethod,
)
from tisit_keycloak_adapter.schemas.authorization_result import AuthorizationResult
from tisit_keycloak_adapter.schemas.keycloak_configuration import (
    KeycloakConfiguration,
)
from tisit_keycloak_adapter.schemas.match_strategy import MatchStrategy
from tisit_keycloak_adapter.schemas.validation_strategy import (
    AuthMetrics,
    ValidationConfig,
    ValidationStrategy,
)

# Global authentication approach - middleware
from tisit_keycloak_adapter.setup import setup_keycloak_middleware

# Selective authentication approach - DI dependencies
from tisit_keycloak_adapter.setup_keycloak import (
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
