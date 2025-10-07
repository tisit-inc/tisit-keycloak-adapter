"""
This module contains the Keycloak backend.

It is used by the middleware to perform the actual authentication.
"""

import asyncio
import functools
import logging
import threading
import time
import typing
from datetime import datetime

import keycloak
from cachetools import TTLCache
from jwcrypto import jwk
from keycloak import KeycloakAdmin, KeycloakOpenID
from starlette.authentication import (
    AuthenticationBackend,
    AuthenticationError,
    BaseUser,
)
from starlette.requests import HTTPConnection

from tisit_keycloak_adapter.exceptions import (
    AuthAdminConfigurationError,
    AuthClaimMissing,
    AuthHeaderMissing,
    AuthInvalidToken,
    AuthKeycloakError,
    AuthUserError,
)
from tisit_keycloak_adapter.fast_api_user import EnhancedFastApiUser, FastApiUser
from tisit_keycloak_adapter.schemas.authorization_methods import (
    AuthorizationMethod,
)
from tisit_keycloak_adapter.schemas.keycloak_configuration import (
    KeycloakConfiguration,
)
from tisit_keycloak_adapter.schemas.validation_strategy import (
    AuthMetrics,
    ValidationConfig,
    ValidationStrategy,
)

log = logging.getLogger(__name__)


class KeycloakBackend(AuthenticationBackend):
    """
    Backend to perform authentication using Keycloak
    """

    def __init__(
        self,
        keycloak_configuration: KeycloakConfiguration,
        user_mapper: typing.Callable[[typing.Dict[str, typing.Any]], typing.Awaitable[typing.Any]]
        | None = None,
        validation_config: ValidationConfig | None = None,
    ):
        self.keycloak_configuration = keycloak_configuration
        self.validation_config = validation_config or ValidationConfig()
        self.keycloak_openid = self._get_keycloak_openid()
        if not self.keycloak_configuration.use_introspection_endpoint:
            self.public_key = self._get_public_key()
        self.get_user = user_mapper if user_mapper else KeycloakBackend._get_user

        # Add new capabilities
        self.metrics = AuthMetrics()
        self._validation_times: list[float] = []
        self.cache = TTLCache(maxsize=1000, ttl=self.validation_config.cache_ttl_seconds)
        self._last_periodic_checks: dict[str, datetime] = {}
        self._keycloak_admin: KeycloakAdmin | None = None
        self._admin_client_lock = threading.Lock()
        self._client_uuid: str | None = None

    def _get_keycloak_openid(self) -> KeycloakOpenID:
        """
        Instance-scoped KeycloakOpenID object
        """
        return KeycloakOpenID(
            server_url=self.keycloak_configuration.url,
            client_id=self.keycloak_configuration.client_id,
            realm_name=self.keycloak_configuration.realm,
            client_secret_key=self.keycloak_configuration.client_secret,
            verify=self.keycloak_configuration.verify,
        )

    def _get_public_key(self) -> jwk.JWK:
        """
        Returns the public key used to validate tokens.
        This is only used if the introspection endpoint is not used.
        """
        log.debug("Fetching public key from Keycloak server at %s", self.keycloak_configuration.url)
        try:
            key = (
                "-----BEGIN PUBLIC KEY-----\n"
                + self.keycloak_openid.public_key()
                + "\n-----END PUBLIC KEY-----"
            )
            return jwk.JWK.from_pem(key.encode("utf-8"))
        except keycloak.exceptions.KeycloakGetError as exc:
            log.error("Failed to fetch public key from Keycloak server: %s", exc.error_message)
            raise AuthKeycloakError from exc

    @staticmethod
    async def _get_user(userinfo: typing.Dict[str, typing.Any]) -> BaseUser:
        """
        Default implementation of the get_user method.
        """
        return FastApiUser(
            first_name=userinfo.get("given_name", ""),
            last_name=userinfo.get("family_name", ""),
            user_id=userinfo.get("user_id", ""),
        )

    async def authenticate(self, conn: HTTPConnection) -> tuple[list[str], BaseUser | None]:
        """
        The authenticate method is invoked each time a route is called that
        the middleware is applied to.
        """

        # If this is a websocket connection, we can extract the token
        # from the cookies
        if (
            self.keycloak_configuration.enable_websocket_support
            and conn.headers.get("upgrade") == "websocket"
        ):
            auth_header = conn.cookies.get(self.keycloak_configuration.websocket_cookie_name, None)
        else:
            auth_header = conn.headers.get("Authorization", None)

        if not auth_header:
            raise AuthHeaderMissing

        # Check if token starts with the authentication scheme
        token = auth_header.split(" ")
        if len(token) != 2 or token[0] != self.keycloak_configuration.authentication_scheme:
            raise AuthInvalidToken

        # Depending on the chosen method by the user, either
        # use the introspection endpoint or decode the token
        if self.keycloak_configuration.use_introspection_endpoint:
            log.debug("Using introspection endpoint to validate token")
            # Call introspect endpoint to check if token is valid
            try:
                token_info = await self.keycloak_openid.a_introspect(token[1])
            except keycloak.exceptions.KeycloakPostError as exc:
                raise AuthKeycloakError from exc
        else:
            log.debug("Using keycloak public key to validate token")
            # Decode Token locally using the public key
            token_info = await self.keycloak_openid.a_decode_token(
                token[1],
                self.keycloak_configuration.validate_token,
                **self.keycloak_configuration.validation_options,
                key=self.public_key,
            )

        # Calculate claims to extract
        # Default is user configured claims
        claims = self.keycloak_configuration.claims
        # If device auth is enabled + device claim is present...
        if (
            self.keycloak_configuration.enable_device_authentication
            and self.keycloak_configuration.device_authentication_claim in token_info
        ):
            # ...only add the device auth claim to the claims to extract
            claims = [self.keycloak_configuration.device_authentication_claim]
            # If claim based authorization is enabled...
            if self.keycloak_configuration.authorization_method == AuthorizationMethod.CLAIM:
                # ...add the authorization claim to the claims to extract
                claims.append(self.keycloak_configuration.authorization_claim)

        # Extract claims from token
        user_info = {}
        for claim in claims:
            try:
                user_info[claim] = token_info[claim]
            except KeyError:
                log.warning("Claim %s is configured but missing in the token", claim)
                if self.keycloak_configuration.reject_on_missing_claim:
                    log.warning("Rejecting request because of missing claim")
                    raise AuthClaimMissing from KeyError
                log.debug("Backend is configured to ignore missing claims, continuing...")

        # Handle Authorization depending on the Claim Method
        scope_auth = None
        if self.keycloak_configuration.authorization_method == AuthorizationMethod.CLAIM:
            if self.keycloak_configuration.authorization_claim not in token_info:
                raise AuthClaimMissing
            scope_auth = token_info[self.keycloak_configuration.authorization_claim]

        # Check if the device authentication claim is present and evaluated to true
        # If so, the rest (mapping claims, user mapper, authorization) is skipped
        if self.keycloak_configuration.enable_device_authentication:
            log.debug("Device authentication is enabled, checking for device claim")
            try:
                if token_info[self.keycloak_configuration.device_authentication_claim]:
                    log.info("Request contains a device token, skipping user mapping")
                    return scope_auth, None
            except KeyError:
                log.debug(
                    "Device authentication claim is missing in the token, "
                    "proceeding with normal authentication"
                )

        # Call user function to get user object
        try:
            user = await self.get_user(user_info)
        except Exception as exc:
            log.warning(
                "Error while getting user object: %s. "
                "The user-provided function raised an exception",
                exc,
            )
            raise AuthUserError from exc

        if not user:
            log.warning("User object is None. The user-provided function returned None")
            raise AuthUserError

        return scope_auth, user

    # === NEW DI-FIRST METHODS ===

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
        return token_hash in self.cache

    def _should_do_periodic_check(self, token_hash: str) -> bool:
        """Check if periodic introspection is needed."""
        if token_hash not in self._last_periodic_checks:
            return True

        last_check = self._last_periodic_checks[token_hash]
        time_since_check = datetime.now() - last_check
        return time_since_check.total_seconds() >= self.validation_config.periodic_check_interval

    async def get_userinfo(self, token: str) -> dict[str, typing.Any]:
        """
        Get user information from token using local JWT validation.
        """
        try:
            if self.keycloak_configuration.use_introspection_endpoint:
                return await self.introspect_token(token)

            # Use local JWT validation
            if not hasattr(self, "public_key"):
                self.public_key = self._get_public_key()

            token_info = await self.keycloak_openid.a_decode_token(
                token,
                self.keycloak_configuration.validate_token,
                **self.keycloak_configuration.validation_options,
                key=self.public_key,
            )

            return token_info

        except keycloak.exceptions.KeycloakGetError as exc:
            log.error(f"Failed to get user info: {exc.error_message}")
            raise AuthenticationError("Invalid token") from exc
        except Exception as exc:
            log.error(f"Token validation failed: {exc}")
            raise AuthenticationError("Token validation failed") from exc

    async def introspect_token(self, token: str) -> dict[str, typing.Any]:
        """
        Introspect token using Keycloak introspection endpoint.
        """
        try:
            token_info = await self.keycloak_openid.a_introspect(token)

            if not token_info.get("active", False):
                raise AuthenticationError("Token is not active")

            return token_info

        except keycloak.exceptions.KeycloakPostError as exc:
            log.error(f"Token introspection failed: {exc.error_message}")
            raise AuthenticationError("Token introspection failed") from exc
        except Exception as exc:
            log.error(f"Introspection error: {exc}")
            raise AuthenticationError("Introspection failed") from exc

    async def validate_token_with_strategy(
        self, token: str, strategy: ValidationStrategy
    ) -> EnhancedFastApiUser:
        """
        Validate token using the specified strategy.
        """
        start_time = time.time()
        token_hash = str(hash(token))

        try:
            if strategy == ValidationStrategy.JWT_LOCAL:
                result = await self._validate_jwt_local(token)

            elif strategy == ValidationStrategy.JWT_WITH_FALLBACK:
                result = await self._validate_jwt_with_fallback(token, token_hash)

            elif strategy == ValidationStrategy.INTROSPECTION_ONLY:
                result = await self._validate_introspection_only(token, token_hash)

            elif strategy == ValidationStrategy.JWT_WITH_PERIODIC_CHECK:
                result = await self._validate_jwt_with_periodic_check(token, token_hash)

            else:
                raise ValueError(f"Unknown validation strategy: {strategy}")

            validation_time_ms = (time.time() - start_time) * 1000
            self._record_validation_time(validation_time_ms)

            return result

        except Exception as e:
            self.metrics.validation_failures += 1
            log.error(f"Token validation failed with strategy {strategy}: {e}")
            raise AuthenticationError("Token validation failed")

    async def _validate_jwt_local(self, token: str) -> EnhancedFastApiUser:
        """Validate token using only local JWT validation."""
        self.metrics.jwt_validations += 1

        try:
            userinfo = await self.get_userinfo(token)
            return await self._create_enhanced_user(userinfo)
        except Exception as e:
            log.debug(f"JWT local validation failed: {e}")
            raise

    async def _validate_jwt_with_fallback(self, token: str, token_hash: str) -> EnhancedFastApiUser:
        """Validate token with JWT first, fallback to introspection."""
        try:
            return await self._validate_jwt_local(token)
        except Exception as jwt_error:
            log.debug(f"JWT validation failed, trying introspection fallback: {jwt_error}")
            self.metrics.fallback_triggers += 1

            try:
                return await self._validate_introspection_only(token, token_hash)
            except Exception as introspection_error:
                log.error(f"Both JWT and introspection validation failed: {introspection_error}")
                raise AuthenticationError("Token validation failed")

    async def _validate_introspection_only(
        self, token: str, token_hash: str
    ) -> EnhancedFastApiUser:
        """Validate token using only introspection endpoint."""
        # Check cache first
        if self.validation_config.cache_introspection_results and self._is_cache_valid(token_hash):
            self.metrics.cache_hits += 1
            cached_result = self.cache[token_hash]
            return await self._create_enhanced_user(cached_result)

        self.metrics.cache_misses += 1
        self.metrics.introspection_calls += 1

        try:
            userinfo = await self.introspect_token(token)

            # Cache the result
            if self.validation_config.cache_introspection_results:
                self.cache[token_hash] = userinfo

            return await self._create_enhanced_user(userinfo)
        except Exception as e:
            log.error(f"Introspection validation failed: {e}")
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
                import asyncio

                asyncio.create_task(self._background_introspection_check(token, token_hash))
                self._last_periodic_checks[token_hash] = datetime.now()
            except Exception as e:
                log.warning(f"Background introspection check failed: {e}")

        return jwt_result

    async def _background_introspection_check(self, token: str, token_hash: str) -> None:
        """Perform background introspection check for token validity."""
        try:
            userinfo = await self.introspect_token(token)
            if not userinfo.get("active", False):
                log.warning(
                    f"Token {token_hash[:8]}... is no longer active according to introspection"
                )
                # Could implement token blacklisting here
        except Exception as e:
            log.warning(f"Background introspection check failed for token {token_hash[:8]}...: {e}")

    async def _create_enhanced_user(self, userinfo: dict[str, typing.Any]) -> EnhancedFastApiUser:
        """Create EnhancedFastApiUser from userinfo."""
        return EnhancedFastApiUser.from_userinfo(userinfo, self.keycloak_configuration.claims)

    def get_metrics(self) -> AuthMetrics:
        """Get current authentication metrics."""
        return self.metrics.model_copy()

    def reset_metrics(self) -> None:
        """Reset authentication metrics."""
        self.metrics = AuthMetrics()
        self._validation_times.clear()

    # === ADMIN CLIENT UTILITIES ===

    def _admin_credentials_provided(self) -> bool:
        """Check whether admin-capable credentials were configured."""
        return bool(self.keycloak_configuration.client_secret)

    def _get_admin_client(self) -> KeycloakAdmin:
        """Get or create the KeycloakAdmin client for management operations."""
        if not self._admin_credentials_provided():
            raise AuthAdminConfigurationError(
                "Keycloak client_secret is required for admin operations."
            )

        if self._keycloak_admin is not None:
            return self._keycloak_admin

        with self._admin_client_lock:
            if self._keycloak_admin is None:
                secret = self.keycloak_configuration.client_secret
                if not secret:
                    raise AuthAdminConfigurationError(
                        "Keycloak client_secret is required for admin operations."
                    )

                self._keycloak_admin = KeycloakAdmin(
                    server_url=self.keycloak_configuration.url,
                    realm_name=self.keycloak_configuration.realm,
                    client_id=self.keycloak_configuration.client_id,
                    client_secret_key=str(secret),
                    verify=self.keycloak_configuration.verify,
                )

        return self._keycloak_admin

    async def _admin_call(self, method_name: str, *args, **kwargs):
        """Invoke a KeycloakAdmin method, preferring async variants when available."""
        admin_client = self._get_admin_client()

        async_method = getattr(admin_client, f"a_{method_name}", None)
        if callable(async_method):
            return await async_method(*args, **kwargs)

        sync_method = getattr(admin_client, method_name, None)
        if callable(sync_method):
            return await asyncio.to_thread(
                functools.partial(sync_method, *args, **kwargs)
            )

        raise AttributeError(f"KeycloakAdmin has no method '{method_name}' or 'a_{method_name}'.")

    async def _get_client_uuid(self) -> str:
        """Resolve and cache the internal Keycloak client identifier."""
        if self._client_uuid:
            return self._client_uuid

        client_identifier = self.keycloak_configuration.client_id

        try:
            client_uuid = await self._admin_call("get_client_id", client_identifier)
        except keycloak.exceptions.KeycloakGetError as exc:
            log.error(f"Failed to resolve client id '{client_identifier}': {exc.error_message}")
            raise AuthKeycloakError from exc

        if not client_uuid:
            msg = f"Client '{client_identifier}' not found in Keycloak."
            log.error(msg)
            raise AuthKeycloakError(msg)

        self._client_uuid = client_uuid
        return client_uuid

    # === USER MANAGEMENT METHODS ===

    async def get_user_details(self, user_id: str) -> dict[str, typing.Any]:
        """
        Get detailed information about a user.

        :param user_id: User ID (sub claim)
        :return: Dictionary containing user information
        """
        try:
            user_info = await self._admin_call("get_user", user_id)
            return user_info
        except keycloak.exceptions.KeycloakGetError as exc:
            log.error(f"Failed to get user details: {exc.error_message}")
            raise AuthKeycloakError from exc

    async def update_user_attributes(self, user_id: str, attributes: dict[str, typing.Any]) -> bool:
        """
        Update user attributes in Keycloak.

        :param user_id: User ID (sub claim)
        :param attributes: Dictionary of attributes to update
        :return: True if successful
        """
        if not attributes:
            return True

        normalized: dict[str, typing.Any] = {}
        for key, value in attributes.items():
            if value is None:
                normalized[key] = None
            elif isinstance(value, list):
                normalized[key] = [str(item) for item in value]
            elif isinstance(value, tuple | set):
                normalized[key] = [str(item) for item in value]
            else:
                normalized[key] = [str(value)]

        payload = {"attributes": normalized}

        try:
            await self._admin_call(
                "update_user", user_id, payload=payload
            )
            return True
        except keycloak.exceptions.KeycloakPostError as exc:
            log.error(f"Failed to update user attributes: {exc.error_message}")
            raise AuthKeycloakError from exc

    async def set_user_attribute(
        self,
        user_id: str,
        attribute: str | dict[str, typing.Any],
        value: typing.Any | None = None,
    ) -> bool:
        """
        Convenience helper to update one or more user attributes.

        Accepts either a mapping of attributes or a single attribute name/value pair.
        """

        if isinstance(attribute, dict):
            attributes = attribute
        else:
            attributes = {attribute: value}

        return await self.update_user_attributes(user_id, attributes)

    async def get_user_roles(self, user_id: str) -> list[str]:
        """
        Get all roles assigned to a user.

        :param user_id: User ID (sub claim)
        :return: List of role names
        """
        try:
            roles: list[str] = []

            realm_roles = await self._admin_call("get_realm_roles_of_user", user_id)
            if realm_roles:
                roles.extend(role["name"] for role in realm_roles if "name" in role)

            try:
                client_uuid = await self._get_client_uuid()
            except AuthKeycloakError:
                client_uuid = None

            if client_uuid:
                client_roles = await self._admin_call(
                    "get_client_roles_of_user", user_id, client_uuid
                )
                if client_roles:
                    client_id = self.keycloak_configuration.client_id
                    roles.extend(
                        f"{client_id}:{role['name']}"
                        for role in client_roles
                        if "name" in role
                    )

            # Preserve order while removing duplicates
            seen = set()
            unique_roles = []
            for role in roles:
                if role not in seen:
                    seen.add(role)
                    unique_roles.append(role)

            return unique_roles

        except keycloak.exceptions.KeycloakGetError as exc:
            log.error(f"Failed to get user roles: {exc.error_message}")
            return []

    async def assign_role_to_user(
        self, user_id: str, role_name: str, is_realm_role: bool = True
    ) -> bool:
        """
        Assign a role to a user.

        :param user_id: User ID (sub claim)
        :param role_name: Name of the role to assign
        :param is_realm_role: True for realm role, False for client role
        :return: True if successful
        """
        try:
            if is_realm_role:
                role_representation = await self._admin_call("get_realm_role", role_name)
                await self._admin_call("assign_realm_roles", user_id, [role_representation])
            else:
                client_uuid = await self._get_client_uuid()
                role_representation = await self._admin_call(
                    "get_client_role", client_uuid, role_name
                )
                await self._admin_call(
                    "assign_client_role", user_id, client_uuid, [role_representation]
                )
            return True
        except (
            keycloak.exceptions.KeycloakGetError,
            keycloak.exceptions.KeycloakPostError,
        ) as exc:
            log.error(f"Failed to assign role '{role_name}': {exc.error_message}")
            raise AuthKeycloakError from exc

    async def remove_role_from_user(
        self, user_id: str, role_name: str, is_realm_role: bool = True
    ) -> bool:
        """
        Remove a role from a user.

        :param user_id: User ID (sub claim)
        :param role_name: Name of the role to remove
        :param is_realm_role: True for realm role, False for client role
        :return: True if successful
        """
        try:
            if is_realm_role:
                role_representation = await self._admin_call("get_realm_role", role_name)
                await self._admin_call(
                    "delete_realm_roles_of_user", user_id, [role_representation]
                )
            else:
                client_uuid = await self._get_client_uuid()
                role_representation = await self._admin_call(
                    "get_client_role", client_uuid, role_name
                )
                await self._admin_call(
                    "delete_client_roles_of_user", user_id, client_uuid, [role_representation]
                )
            return True
        except (
            keycloak.exceptions.KeycloakGetError,
            keycloak.exceptions.KeycloakPostError,
        ) as exc:
            log.error(f"Failed to remove role '{role_name}': {exc.error_message}")
            raise AuthKeycloakError from exc

    async def get_user_sessions(self, user_id: str) -> list[dict[str, typing.Any]]:
        """
        Get active sessions for a user.

        :param user_id: User ID (sub claim)
        :return: List of session information
        """
        try:
            sessions = await self._admin_call("get_sessions", user_id)
            return sessions or []
        except keycloak.exceptions.KeycloakGetError as exc:
            log.error(f"Failed to get user sessions: {exc.error_message}")
            return []

    async def logout_user(self, user_id: str) -> bool:
        """
        Logout user from all sessions.

        :param user_id: User ID (sub claim)
        :return: True if successful
        """
        try:
            await self._admin_call("user_logout", user_id)
            return True
        except keycloak.exceptions.KeycloakPostError as exc:
            log.error(f"Failed to logout user: {exc.error_message}")
            raise AuthKeycloakError from exc

    async def get_user_events(self, user_id: str, limit: int = 100) -> list[dict[str, typing.Any]]:
        """
        Get user events/audit log.

        :param user_id: User ID (sub claim)
        :param limit: Maximum number of events to return
        :return: List of user events
        """
        try:
            query: dict[str, typing.Any] = {"user": user_id}
            if limit:
                query["max"] = limit

            events = await self._admin_call("get_events", query)
            return events or []
        except keycloak.exceptions.KeycloakGetError as exc:
            log.error(f"Failed to get user events: {exc.error_message}")
            return []

    async def validate_token_scopes(self, token: str, required_scopes: list[str]) -> bool:
        """
        Validate that token contains required scopes.

        :param token: JWT access token
        :param required_scopes: List of required scopes
        :return: True if all scopes are present
        """
        try:
            userinfo = await self.get_userinfo(token)
            token_scopes = userinfo.get("scope", "").split() if userinfo.get("scope") else []

            return all(scope in token_scopes for scope in required_scopes)
        except Exception:
            return False

    async def get_token_roles(self, token: str) -> list[str]:
        """
        Extract roles from token.

        :param token: JWT access token
        :return: List of user roles
        """
        try:
            userinfo = await self.get_userinfo(token)

            # Try different places where roles might be stored
            roles = []

            # Realm roles
            if "realm_access" in userinfo and "roles" in userinfo["realm_access"]:
                roles.extend(userinfo["realm_access"]["roles"])

            # Resource/client roles
            if "resource_access" in userinfo:
                for client, client_data in userinfo["resource_access"].items():
                    if "roles" in client_data:
                        roles.extend([f"{client}:{role}" for role in client_data["roles"]])

            # Direct roles claim
            if "roles" in userinfo:
                if isinstance(userinfo["roles"], list):
                    roles.extend(userinfo["roles"])
                elif isinstance(userinfo["roles"], str):
                    roles.append(userinfo["roles"])

            return list(set(roles))  # Remove duplicates

        except Exception as exc:
            log.warning(f"Failed to extract roles from token: {exc}")
            return []
