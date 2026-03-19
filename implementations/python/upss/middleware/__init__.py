"""
Security middleware primitives for UPSS v1.1.0.

This package provides pluggable security components that can be composed
to create custom security pipelines.

Essential Primitives:
    - BasicSanitizer: Block common prompt injection patterns
    - LightweightAuditor: Simple access logging
    - SimpleRBAC: Role-based access control
    - InputValidator: Runtime input validation (Gate 1-2)

Advanced Security:
    - ChecksumMiddleware: Supply-chain tampering detection (Gate 5 - CR-03)
    - RateLimitMiddleware: Rate-based abuse prevention (Gate 6 - RS-05)

OWASP LLM01:2025 Controls:
    - RS-01/RS-02: Injection detection (BasicSanitizer)
    - RS-03: Length validation (InputValidator)
    - RS-04: Encoding validation (InputValidator)
    - RS-05: Rate limiting (RateLimitMiddleware)
    - CR-03: Checksum verification (ChecksumMiddleware)
"""

from .auditor import LightweightAuditor
from .checksum import ChecksumMiddleware
from .ratelimit import RateLimitMiddleware
from .rbac import SimpleRBAC
from .sanitizer import BasicSanitizer
from .validator import InputValidator

__all__ = [
    "BasicSanitizer",
    "LightweightAuditor",
    "SimpleRBAC",
    "InputValidator",
    "ChecksumMiddleware",
    "RateLimitMiddleware",
]
