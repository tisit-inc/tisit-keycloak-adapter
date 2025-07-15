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
from fastapi_keycloak_middleware.setup import setup_keycloak_middleware
from fastapi_keycloak_middleware.setup_di import (
    setup_keycloak_di,
    create_global_auth_dependency,
    create_role_based_dependencies,
)
from fastapi_keycloak_middleware.dependency_factory import KeycloakDependencyFactory
from fastapi_keycloak_middleware.enhanced_backend import (
    EnhancedKeycloakBackend,
    EnhancedFastApiUser,
)
from fastapi_keycloak_middleware.schemas.validation_strategy import (
    ValidationStrategy,
    ValidationConfig,
    AuthMetrics,
)

logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    # Legacy middleware approach
    AuthorizationResult.__name__,
    KeycloakMiddleware.__name__,
    KeycloakConfiguration.__name__,
    AuthorizationMethod.__name__,
    MatchStrategy.__name__,
    FastApiUser.__name__,
    CheckPermissions.__name__,
    get_auth.__name__,
    get_user.__name__,
    get_authorization_result.__name__,
    require_permission.__name__,
    setup_keycloak_middleware.__name__,
    strip_request.__name__,
    
    # New DI-first approach
    setup_keycloak_di.__name__,
    create_global_auth_dependency.__name__,
    create_role_based_dependencies.__name__,
    KeycloakDependencyFactory.__name__,
    EnhancedKeycloakBackend.__name__,
    EnhancedFastApiUser.__name__,
    ValidationStrategy.__name__,
    ValidationConfig.__name__,
    AuthMetrics.__name__,
]
