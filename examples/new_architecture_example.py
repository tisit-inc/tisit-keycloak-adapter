"""
Example demonstrating the new DI-first Keycloak architecture.
"""

from fastapi import Depends, FastAPI, HTTPException

# New DI-first imports
from tisit_keycloak_adapter import (
    EnhancedFastApiUser,
    KeycloakBackend,
    KeycloakConfiguration,
    ValidationConfig,
    ValidationStrategy,
    create_admin_dependency,
    create_auth_dependency,
    create_global_auth_dependency,
    create_optional_auth_dependency,
    create_role_based_dependencies,
    get_keycloak_backend_dependency,
    setup_keycloak,
)

app = FastAPI(title="New Keycloak Architecture Example")

# Configuration
keycloak_config = KeycloakConfiguration(
    realm="master",
    url="http://localhost:8080",
    client_id="my-client",
    client_secret="my-secret",
)

# Validation configuration
validation_config = ValidationConfig(
    strategy=ValidationStrategy.JWT_WITH_FALLBACK,
    fallback_timeout_seconds=3.0,
    cache_introspection_results=True,
    cache_ttl_seconds=60,
)

# Create singleton backend
keycloak_backend = setup_keycloak(
    app=app,
    keycloak_configuration=keycloak_config,
    validation_config=validation_config,
    add_swagger_auth=True,
    add_metrics_endpoint=True,
    metrics_endpoint_path="/auth/metrics",
)

# Create dependencies
user_auth = create_auth_dependency(
    keycloak_backend, strategy=ValidationStrategy.JWT_LOCAL, require_roles=["user"]
)

admin_auth = create_admin_dependency(
    keycloak_backend,
    strategy=ValidationStrategy.INTROSPECTION_ONLY,  # High security for admins
)

optional_auth = create_optional_auth_dependency(keycloak_backend)

# Role-based dependencies
role_deps = create_role_based_dependencies(
    keycloak_backend,
    {
        "admin": ["admin", "super_admin"],
        "user": ["user", "admin", "super_admin"],
        "moderator": ["moderator", "admin"],
    },
)

# Backend dependency for user management
backend_dep = get_keycloak_backend_dependency(keycloak_backend)

# Global auth for API routes
api_auth = create_global_auth_dependency(keycloak_backend, require_roles=["user"])

# API router with global auth
from fastapi import APIRouter

api_router = APIRouter(prefix="/api")

# Apply global auth to all /api/* routes
app.include_router(api_router, dependencies=[Depends(api_auth)])

# Routes


@app.get("/")
async def root():
    """Public endpoint - no authentication required."""
    return {"message": "Public endpoint"}


@app.get("/health")
async def health():
    """Health check - no authentication required."""
    return {"status": "healthy"}


@app.get("/maybe-protected")
async def maybe_protected(user: EnhancedFastApiUser | None = Depends(optional_auth)):
    """Endpoint with optional authentication."""
    if user:
        return {"message": f"Hello {user.username}!", "authenticated": True, "roles": user.roles}
    else:
        return {"message": "Hello anonymous user!", "authenticated": False}


@app.get("/protected")
async def protected(user: EnhancedFastApiUser = Depends(user_auth)):
    """Protected endpoint requiring user role."""
    return {
        "message": f"Hello {user.username}!",
        "user_id": user.user_id,
        "email": user.email,
        "roles": user.roles,
        "scopes": user.scopes,
    }


@app.get("/admin-only")
async def admin_only(user: EnhancedFastApiUser = Depends(admin_auth)):
    """Admin-only endpoint with high security validation."""
    return {
        "message": "Admin access granted",
        "user": user.username,
        "admin_roles": [role for role in user.roles if "admin" in role.lower()],
    }


@app.get("/role-based")
async def role_based(user: EnhancedFastApiUser = Depends(role_deps["moderator"])):
    """Endpoint requiring moderator role."""
    return {"message": "Moderator access granted", "user": user.username, "roles": user.roles}


# API routes (all require authentication due to global dependency)
@api_router.get("/profile")
async def get_profile(user: EnhancedFastApiUser = Depends(user_auth)):
    """Get user profile."""
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


@api_router.get("/data")
async def get_data(user: EnhancedFastApiUser = Depends(user_auth)):
    """Get user data - authentication inherited from router."""
    return {"data": f"Data for {user.username}", "user_id": user.user_id}


# User management endpoints (require backend access)
@app.get("/admin/user/{user_id}/details")
async def get_user_details(
    user_id: str,
    current_user: EnhancedFastApiUser = Depends(admin_auth),
    backend: KeycloakBackend = Depends(backend_dep),
):
    """Get detailed user information (admin only)."""
    try:
        user_details = await backend.get_user_details(user_id)
        user_roles = await backend.get_user_roles(user_id)
        active_sessions = await backend.get_user_sessions(user_id)

        return {
            "user_details": user_details,
            "roles": user_roles,
            "active_sessions": len(active_sessions),
            "requested_by": current_user.username,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/admin/user/{user_id}/role")
async def assign_role(
    user_id: str,
    role_name: str,
    is_realm_role: bool = True,
    current_user: EnhancedFastApiUser = Depends(admin_auth),
    backend: KeycloakBackend = Depends(backend_dep),
):
    """Assign role to user (admin only)."""
    try:
        success = await backend.assign_role_to_user(user_id, role_name, is_realm_role)
        return {
            "success": success,
            "message": f"Role '{role_name}' assigned to user {user_id}",
            "assigned_by": current_user.username,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/admin/user/{user_id}/logout")
async def logout_user(
    user_id: str,
    current_user: EnhancedFastApiUser = Depends(admin_auth),
    backend: KeycloakBackend = Depends(backend_dep),
):
    """Logout user from all sessions (admin only)."""
    try:
        success = await backend.logout_user(user_id)
        return {
            "success": success,
            "message": f"User {user_id} logged out from all sessions",
            "logged_out_by": current_user.username,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/admin/user/{user_id}/attributes")
async def update_user_attributes(
    user_id: str,
    attributes: dict,
    current_user: EnhancedFastApiUser = Depends(admin_auth),
    backend: KeycloakBackend = Depends(backend_dep),
):
    """Update user attributes (admin only)."""
    try:
        success = await backend.update_user_attributes(user_id, attributes)
        return {
            "success": success,
            "message": f"Attributes updated for user {user_id}",
            "attributes": attributes,
            "updated_by": current_user.username,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Chat service example - updating user info
@app.post("/chat/user/{user_id}/update-preferences")
async def update_chat_preferences(
    user_id: str,
    preferences: dict,
    current_user: EnhancedFastApiUser = Depends(user_auth),
    backend: KeycloakBackend = Depends(backend_dep),
):
    """Update user chat preferences."""
    # Check if user can update their own preferences or is admin
    if current_user.user_id != user_id and not current_user.has_role("admin"):
        raise HTTPException(status_code=403, detail="Can only update your own preferences")

    try:
        # Update user attributes in Keycloak
        attributes = {"chat_preferences": preferences, "last_chat_update": "2024-01-01T00:00:00Z"}

        success = await backend.update_user_attributes(user_id, attributes)
        return {
            "success": success,
            "message": "Chat preferences updated",
            "preferences": preferences,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Metrics endpoint is automatically added at /auth/metrics (admin protected)

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
