"""
Universal Prompt Security Standard (UPSS) - Python Implementation

A secure, production-ready library for managing LLM prompts following the UPSS
framework.

Version 1.1.0 introduces a modular middleware architecture for composable security.
"""

__version__ = "1.1.0"
__author__ = "Alvin T. Veroy"

# Legacy client (v1.x compatibility)
from .core.client import UPSSClient

# Core exceptions
from .core.exceptions import (
    ComplianceError,
    ConfigurationError,
    ConflictError,
    IntegrityError,
    NotFoundError,
    PermissionError,
    SecurityError,
    StorageError,
    UPSSError,
)

# v2.0 Middleware Architecture
from .core.middleware import (
    SecurityContext,
    SecurityMiddleware,
    SecurityPipeline,
    SecurityResult,
)

# Core models
from .core.models import AuditEntry, MigrationReport, PromptContent

# Essential Security Primitives
from .middleware import (
    BasicSanitizer,
    ChecksumMiddleware,
    InputValidator,
    LightweightAuditor,
    RateLimitMiddleware,
    SimpleRBAC,
)

__all__ = [
    # Legacy v1.x
    "UPSSClient",
    "UPSSError",
    "ConfigurationError",
    "StorageError",
    "IntegrityError",
    "PermissionError",
    "NotFoundError",
    "ConflictError",
    "ComplianceError",
    "SecurityError",
    "PromptContent",
    "AuditEntry",
    "MigrationReport",
    # v2.0 Middleware
    "SecurityPipeline",
    "SecurityMiddleware",
    "SecurityContext",
    "SecurityResult",
    "BasicSanitizer",
    "LightweightAuditor",
    "SimpleRBAC",
    "InputValidator",
    "ChecksumMiddleware",
    "RateLimitMiddleware",
]
