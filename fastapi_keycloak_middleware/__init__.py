"""
Middleware for FastAPI that supports authenticating users against Keycloak
"""

__version__ = "1.3.0"

import logging

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
# Legacy middleware approach (backwards compatibility)
from fastapi_keycloak_middleware.setup import setup_keycloak_middleware

# New DI-first approach - main API
from fastapi_keycloak_middleware.setup_keycloak import (
    setup_keycloak,
    create_keycloak_singleton,
    setup_swagger_only,
)
from fastapi_keycloak_middleware.dependencies import (
    create_auth_dependency,
    create_optional_auth_dependency,
    create_admin_dependency,
    create_role_based_dependencies,
    create_global_auth_dependency,
    get_keycloak_backend_dependency,
)
from fastapi_keycloak_middleware.keycloak_backend import (
    KeycloakBackend,
    EnhancedFastApiUser,
)
from fastapi_keycloak_middleware.schemas.validation_strategy import (
    ValidationStrategy,
    ValidationConfig,
    AuthMetrics,
)

logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    # Legacy middleware approach (backwards compatibility)
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
    
    # New DI-first approach - main API
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
