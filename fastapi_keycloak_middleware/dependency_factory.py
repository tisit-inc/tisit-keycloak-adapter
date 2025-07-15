"""
Dependency factory for creating Keycloak authentication dependencies with flexible strategies.
"""

import asyncio
import logging
import time
from collections.abc import Callable
from datetime import datetime
from typing import Any, Optional

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi_keycloak_middleware.enhanced_backend import (
    EnhancedFastApiUser,
    EnhancedKeycloakBackend,
)
from fastapi_keycloak_middleware.schemas.keycloak_configuration import (
    KeycloakConfiguration,
)
from fastapi_keycloak_middleware.schemas.validation_strategy import (
    AuthMetrics,
    ValidationConfig,
    ValidationStrategy,
)
from starlette.authentication import AuthenticationError

logger = logging.getLogger(__name__)


class KeycloakDependencyFactory:
    """
    Factory for creating Keycloak authentication dependencies with flexible validation strategies.

    This class provides a DI-first approach to Keycloak authentication, allowing for flexible
    configuration of validation strategies, role-based access control, and comprehensive metrics.
    """

    def __init__(
        self,
        keycloak_configuration: KeycloakConfiguration,
        validation_config: Optional[ValidationConfig] = None,
        user_mapper: Optional[Callable[[dict[str, Any]], Any]] = None,
        scope_mapper: Optional[Callable[[list[str]], list[str]]] = None,
    ):
        self.keycloak_config = keycloak_configuration
        self.validation_config = validation_config or ValidationConfig()
        self.user_mapper = user_mapper
        self.scope_mapper = scope_mapper

        self.backend = EnhancedKeycloakBackend(keycloak_configuration)
        self.security = HTTPBearer(auto_error=False)

        # Metrics tracking
        self.metrics = AuthMetrics()
        self._validation_times: list[float] = []

        # Caching for introspection results
        self._introspection_cache: dict[str, dict[str, Any]] = {}
        self._cache_timestamps: dict[str, datetime] = {}

        # Periodic check tracking
        self._last_periodic_checks: dict[str, datetime] = {}

        logger.info(
            f"KeycloakDependencyFactory initialized with strategy: {self.validation_config.strategy}"
        )

    def _record_validation_time(self, validation_time_ms: float) -> None:
        """Record validation time for metrics."""
        self._validation_times.append(validation_time_ms)
        if len(self._validation_times) > 1000:  # keep last 1000 measurements
            self._validation_times = self._validation_times[-1000:]

        if self._validation_times:
            self.metrics.average_validation_time_ms = sum(self._validation_times) / len(
                self._validation_times
            )

    def _is_cache_valid(self, token_hash: str) -> bool:
        """Check if cached introspection result is still valid."""
        if token_hash not in self._cache_timestamps:
            return False

        cache_age = datetime.now() - self._cache_timestamps[token_hash]
        return cache_age.total_seconds() < self.validation_config.cache_ttl_seconds

    def _cache_introspection_result(self, token_hash: str, result: dict[str, Any]) -> None:
        """Cache introspection result."""
        if self.validation_config.cache_introspection_results:
            self._introspection_cache[token_hash] = result
            self._cache_timestamps[token_hash] = datetime.now()

    def _get_cached_introspection_result(self, token_hash: str) -> Optional[dict[str, Any]]:
        """Get cached introspection result if valid."""
        if not self.validation_config.cache_introspection_results:
            return None

        if self._is_cache_valid(token_hash):
            self.metrics.cache_hits += 1
            return self._introspection_cache.get(token_hash)

        self.metrics.cache_misses += 1
        return None

    def _should_do_periodic_check(self, token_hash: str) -> bool:
        """Check if periodic introspection is needed."""
        if token_hash not in self._last_periodic_checks:
            return True

        last_check = self._last_periodic_checks[token_hash]
        time_since_check = datetime.now() - last_check
        return time_since_check.total_seconds() >= self.validation_config.periodic_check_interval

    async def _validate_token_with_strategy(
        self, token: str, strategy: Optional[ValidationStrategy] = None
    ) -> EnhancedFastApiUser:
        """
        Validate token using the specified or configured strategy.
        """
        start_time = time.time()
        validation_strategy = strategy or self.validation_config.strategy
        token_hash = str(hash(token))

        try:
            if validation_strategy == ValidationStrategy.JWT_LOCAL:
                result = await self._validate_jwt_local(token)

            elif validation_strategy == ValidationStrategy.JWT_WITH_FALLBACK:
                result = await self._validate_jwt_with_fallback(token, token_hash)

            elif validation_strategy == ValidationStrategy.INTROSPECTION_ONLY:
                result = await self._validate_introspection_only(token, token_hash)

            elif validation_strategy == ValidationStrategy.JWT_WITH_PERIODIC_CHECK:
                result = await self._validate_jwt_with_periodic_check(token, token_hash)

            else:
                raise ValueError(f"Unknown validation strategy: {validation_strategy}")

            validation_time_ms = (time.time() - start_time) * 1000
            self._record_validation_time(validation_time_ms)

            return result

        except Exception as e:
            self.metrics.validation_failures += 1
            logger.error(f"Token validation failed with strategy {validation_strategy}: {e}")
            raise AuthenticationError("Token validation failed")

    async def _validate_jwt_local(self, token: str) -> EnhancedFastApiUser:
        """Validate token using only local JWT validation."""
        self.metrics.jwt_validations += 1

        try:
            userinfo = await self.backend.get_userinfo(token)
            return await self._create_user(userinfo)
        except Exception as e:
            logger.debug(f"JWT local validation failed: {e}")
            raise

    async def _validate_jwt_with_fallback(self, token: str, token_hash: str) -> EnhancedFastApiUser:
        """Validate token with JWT first, fallback to introspection."""
        try:
            return await self._validate_jwt_local(token)
        except Exception as jwt_error:
            logger.debug(f"JWT validation failed, trying introspection fallback: {jwt_error}")
            self.metrics.fallback_triggers += 1

            try:
                return await self._validate_introspection_only(token, token_hash)
            except Exception as introspection_error:
                logger.error(f"Both JWT and introspection validation failed: {introspection_error}")
                raise AuthenticationError("Token validation failed")

    async def _validate_introspection_only(
        self, token: str, token_hash: str
    ) -> EnhancedFastApiUser:
        """Validate token using only introspection endpoint."""
        # Check cache first
        cached_result = self._get_cached_introspection_result(token_hash)
        if cached_result:
            return await self._create_user(cached_result)

        self.metrics.introspection_calls += 1

        try:
            userinfo = await self.backend.introspect_token(token)
            if not userinfo.get("active", False):
                raise AuthenticationError("Token is not active")

            # Cache the result
            self._cache_introspection_result(token_hash, userinfo)

            return await self._create_user(userinfo)
        except Exception as e:
            logger.error(f"Introspection validation failed: {e}")
            raise

    async def _validate_jwt_with_periodic_check(
        self, token: str, token_hash: str
    ) -> EnhancedFastApiUser:
        """Validate token with JWT and periodic introspection checks."""
        # Always try JWT first
        jwt_result = await self._validate_jwt_local(token)

        # Check if periodic introspection is needed
        if self._should_do_periodic_check(token_hash):
            try:
                # Background introspection check (don't await to avoid blocking)
                asyncio.create_task(self._background_introspection_check(token, token_hash))
                self._last_periodic_checks[token_hash] = datetime.now()
            except Exception as e:
                logger.warning(f"Background introspection check failed: {e}")

        return jwt_result

    async def _background_introspection_check(self, token: str, token_hash: str) -> None:
        """Perform background introspection check for token validity."""
        try:
            userinfo = await self.backend.introspect_token(token)
            if not userinfo.get("active", False):
                logger.warning(
                    f"Token {token_hash[:8]}... is no longer active according to introspection"
                )
                # Could implement token blacklisting here
        except Exception as e:
            logger.warning(
                f"Background introspection check failed for token {token_hash[:8]}...: {e}"
            )

    async def _create_user(self, userinfo: dict[str, Any]) -> EnhancedFastApiUser:
        """Create FastApiUser from userinfo."""
        if self.user_mapper:
            user = await self.user_mapper(userinfo)
        else:
            user = EnhancedFastApiUser.from_userinfo(userinfo, self.keycloak_config.claims)

        if self.scope_mapper and hasattr(user, "scopes"):
            user.scopes = await self.scope_mapper(user.scopes or [])

        return user

    def create_auth_dependency(
        self,
        strategy: Optional[ValidationStrategy] = None,
        require_roles: Optional[list[str]] = None,
        require_scopes: Optional[list[str]] = None,
        require_all_roles: bool = True,
        require_all_scopes: bool = True,
    ) -> Callable:
        """
        Create an authentication dependency with specified requirements.

        :param strategy: Override validation strategy for this dependency
        :param require_roles: List of required roles
        :param require_scopes: List of required scopes
        :param require_all_roles: Whether all roles are required (AND) or any (OR)
        :param require_all_scopes: Whether all scopes are required (AND) or any (OR)
        """

        async def auth_dependency(
            credentials: Optional[HTTPAuthorizationCredentials] = Depends(self.security),
        ) -> EnhancedFastApiUser:
            if not credentials:
                raise HTTPException(status_code=401, detail="Authorization header missing")

            if not credentials.credentials:
                raise HTTPException(status_code=401, detail="Token missing")

            try:
                user = await self._validate_token_with_strategy(credentials.credentials, strategy)

                # Check role requirements
                if require_roles:
                    user_roles = set(getattr(user, "roles", []) or [])
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
                    user_scopes = set(getattr(user, "scopes", []) or [])
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
            except Exception as e:
                logger.error(f"Authentication failed: {e}")
                raise HTTPException(status_code=500, detail="Authentication error")

        return auth_dependency

    def create_optional_auth_dependency(
        self, strategy: Optional[ValidationStrategy] = None
    ) -> Callable:
        """Create an optional authentication dependency."""

        async def optional_auth_dependency(
            credentials: Optional[HTTPAuthorizationCredentials] = Depends(self.security),
        ) -> Optional[EnhancedFastApiUser]:
            if not credentials or not credentials.credentials:
                return None

            try:
                return await self._validate_token_with_strategy(credentials.credentials, strategy)
            except Exception:
                return None

        return optional_auth_dependency

    def create_admin_dependency(
        self, admin_roles: Optional[list[str]] = None, strategy: Optional[ValidationStrategy] = None
    ) -> Callable:
        """Create a dependency that requires admin roles."""
        admin_roles = admin_roles or ["admin", "administrator"]

        return self.create_auth_dependency(
            strategy=strategy,
            require_roles=admin_roles,
            require_all_roles=False,  # Any admin role is sufficient
        )

    def get_metrics(self) -> AuthMetrics:
        """Get current authentication metrics."""
        return self.metrics.model_copy()

    def reset_metrics(self) -> None:
        """Reset authentication metrics."""
        self.metrics = AuthMetrics()
        self._validation_times.clear()
