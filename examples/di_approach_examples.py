"""
Examples demonstrating the new DI-first approach for Keycloak authentication.
"""

from fastapi import Depends, FastAPI

from tisit_keycloak_adapter import (
    EnhancedFastApiUser,
    KeycloakConfiguration,
    ValidationConfig,
    ValidationStrategy,
    create_global_auth_dependency,
    create_role_based_dependencies,
    setup_keycloak_di,
)

app = FastAPI(title="Keycloak DI Examples")

# Configuration
keycloak_config = KeycloakConfiguration(
    realm="master",
    url="http://localhost:8080",
    client_id="my-client",
    client_secret="my-secret",
)

# Validation configuration with fallback strategy
validation_config = ValidationConfig(
    strategy=ValidationStrategy.JWT_WITH_FALLBACK,
    fallback_timeout_seconds=3.0,
    cache_introspection_results=True,
    cache_ttl_seconds=60,
)

# Setup DI-first Keycloak authentication
dependency_factory = setup_keycloak_di(
    app=app,
    keycloak_configuration=keycloak_config,
    validation_config=validation_config,
    add_swagger_auth=True,
    add_metrics_endpoint=True,
    metrics_endpoint_path="/auth/metrics",
)

# Example 1: Global authentication for all API routes
api_router = FastAPI()

# Apply authentication globally to all routes in this router
global_auth = create_global_auth_dependency(
    dependency_factory,
    require_roles=["user"],  # All routes require 'user' role
)

app.include_router(api_router, prefix="/api", dependencies=[Depends(global_auth)])

# Example 2: Role-based dependencies
role_dependencies = create_role_based_dependencies(
    dependency_factory,
    {
        "admin": ["admin", "super_admin"],
        "user": ["user", "admin", "super_admin"],
        "moderator": ["moderator", "admin"],
    },
)

# Example 3: Different validation strategies for different endpoints
high_security_auth = dependency_factory.create_auth_dependency(
    strategy=ValidationStrategy.INTROSPECTION_ONLY,  # Always verify with Keycloak
    require_roles=["admin"],
)

low_security_auth = dependency_factory.create_auth_dependency(
    strategy=ValidationStrategy.JWT_LOCAL,  # Fast local validation only
    require_roles=["user"],
)

optional_auth = dependency_factory.create_optional_auth_dependency()


# Route examples
@app.get("/public")
async def public_endpoint():
    """Public endpoint - no authentication required."""
    return {"message": "This is a public endpoint"}


@app.get("/protected", dependencies=[Depends(role_dependencies["user"])])
async def protected_endpoint(user: EnhancedFastApiUser = Depends(role_dependencies["user"])):
    """Protected endpoint requiring user role."""
    return {
        "message": f"Hello {user.username}!",
        "user_id": user.user_id,
        "roles": user.roles,
        "email": user.email,
    }


@app.get("/admin-only", dependencies=[Depends(role_dependencies["admin"])])
async def admin_endpoint(user: EnhancedFastApiUser = Depends(role_dependencies["admin"])):
    """Admin-only endpoint."""
    return {
        "message": "Admin access granted",
        "user": user.username,
        "admin_roles": [role for role in user.roles if "admin" in role.lower()],
    }


@app.get("/high-security", dependencies=[Depends(high_security_auth)])
async def high_security_endpoint():
    """High security endpoint with introspection validation."""
    return {"message": "High security endpoint - token verified with Keycloak"}


@app.get("/fast-endpoint", dependencies=[Depends(low_security_auth)])
async def fast_endpoint():
    """Fast endpoint with local JWT validation only."""
    return {"message": "Fast endpoint - local JWT validation"}


@app.get("/optional-auth")
async def optional_auth_endpoint(user: EnhancedFastApiUser | None = Depends(optional_auth)):
    """Endpoint with optional authentication."""
    if user:
        return {
            "message": f"Hello {user.username}!",
            "authenticated": True,
        }
    else:
        return {
            "message": "Hello anonymous user!",
            "authenticated": False,
        }


@app.get("/user-profile")
async def user_profile(
    user: EnhancedFastApiUser = Depends(
        dependency_factory.create_auth_dependency(require_roles=["user"])
    ),
):
    """User profile endpoint showing all available user information."""
    return {
        "profile": {
            "user_id": user.user_id,
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "display_name": user.display_name,
            "roles": user.roles,
            "scopes": user.scopes,
        }
    }


@app.get("/role-check/{required_role}")
async def role_check(
    required_role: str,
    user: EnhancedFastApiUser = Depends(dependency_factory.create_auth_dependency()),
):
    """Dynamic role checking endpoint."""
    has_role = user.has_role(required_role)
    return {
        "required_role": required_role,
        "has_role": has_role,
        "user_roles": user.roles,
    }


# Example 4: Custom dependency with specific requirements
def create_custom_auth():
    """Create a custom authentication dependency with specific requirements."""
    return dependency_factory.create_auth_dependency(
        strategy=ValidationStrategy.JWT_WITH_PERIODIC_CHECK,
        require_roles=["premium_user", "admin"],
        require_scopes=["read:premium", "write:premium"],
        require_all_roles=False,  # Any of the roles is sufficient
        require_all_scopes=True,  # All scopes are required
    )


@app.get("/premium", dependencies=[Depends(create_custom_auth())])
async def premium_endpoint():
    """Premium endpoint with custom authentication requirements."""
    return {"message": "Premium content - custom auth requirements"}


# Example 5: Metrics endpoint (automatically added by setup_keycloak_di)
# Available at /auth/metrics (requires admin role by default)

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
