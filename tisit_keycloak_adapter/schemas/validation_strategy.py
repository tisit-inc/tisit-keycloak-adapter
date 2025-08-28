"""
Validation strategies for token verification.
"""

from enum import Enum

from pydantic import BaseModel, Field


class ValidationStrategy(str, Enum):
    """
    Enum defining different validation strategies for Keycloak tokens.

    - JWT_LOCAL: Only local JWT validation using public key
    - JWT_WITH_FALLBACK: JWT validation with introspection fallback
    - INTROSPECTION_ONLY: Only introspection endpoint validation
    - JWT_WITH_PERIODIC_CHECK: JWT validation with periodic introspection
    """

    JWT_LOCAL = "jwt_local"
    JWT_WITH_FALLBACK = "jwt_with_fallback"
    INTROSPECTION_ONLY = "introspection_only"
    JWT_WITH_PERIODIC_CHECK = "jwt_with_periodic_check"


class ValidationConfig(BaseModel):
    """
    Configuration for token validation strategies.

    :param strategy: The validation strategy to use
    :param fallback_timeout_seconds: Timeout for fallback requests (default: 5.0)
    :param periodic_check_interval: Interval for periodic introspection checks in seconds
        (default: 300)
    :param max_retries: Maximum number of retries for failed requests (default: 3)
    :param cache_introspection_results: Whether to cache introspection results (default: True)
    :param cache_ttl_seconds: TTL for cached introspection results in seconds (default: 60)
    """

    strategy: ValidationStrategy = Field(
        default=ValidationStrategy.JWT_LOCAL, description="The validation strategy to use"
    )
    fallback_timeout_seconds: float = Field(
        default=5.0, description="Timeout for fallback introspection requests"
    )
    periodic_check_interval: int = Field(
        default=300, description="Interval for periodic introspection checks in seconds"
    )
    max_retries: int = Field(default=3, description="Maximum number of retries for failed requests")
    cache_introspection_results: bool = Field(
        default=True, description="Whether to cache introspection results"
    )
    cache_ttl_seconds: int = Field(
        default=60, description="TTL for cached introspection results in seconds"
    )


class AuthMetrics(BaseModel):
    """
    Authentication metrics for monitoring.
    """

    jwt_validations: int = Field(default=0, description="Number of JWT validations")
    introspection_calls: int = Field(default=0, description="Number of introspection calls")
    fallback_triggers: int = Field(default=0, description="Number of fallback triggers")
    validation_failures: int = Field(default=0, description="Number of validation failures")
    cache_hits: int = Field(default=0, description="Number of cache hits")
    cache_misses: int = Field(default=0, description="Number of cache misses")
    average_validation_time_ms: float = Field(
        default=0.0, description="Average validation time in ms"
    )
