"""Security utilities for UPSS."""

import logging
import re
from typing import List, Tuple

logger = logging.getLogger(__name__)

# Dangerous patterns for injection detection
BLOCKLIST_PATTERNS = [
    # Role confusion
    r"you\s+are\s+now",
    r"act\s+as",
    r"pretend\s+to\s+be",
    # Instruction override
    r"ignore\s+previous",
    r"disregard\s+above",
    r"new\s+instructions",
    # Delimiter injection
    r"###",
    r"```",
    r"<\|endoftext\|>",
]

# PII patterns
PII_PATTERNS = {
    "email": r"[\w\.-]+@[\w\.-]+\.\w+",
    "phone": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
}


def sanitize(user_input: str) -> Tuple[str, bool]:
    """
    Sanitize user input to prevent injection attacks.

    Args:
        user_input: Raw user input string

    Returns:
        Tuple of (sanitized_string, is_safe_flag)
    """
    is_safe = True
    sanitized = user_input

    # Escape special characters
    special_chars = {
        '"': "&quot;",
        "'": "&#x27;",
        "{": "&#123;",
        "}": "&#125;",
        "<": "&lt;",
        ">": "&gt;",
    }

    for char, escape in special_chars.items():
        sanitized = sanitized.replace(char, escape)

    # Check for injection patterns
    for pattern in BLOCKLIST_PATTERNS:
        if re.search(pattern, user_input, re.IGNORECASE):
            logger.warning(f"Injection pattern detected: {pattern}")
            is_safe = False

    return sanitized, is_safe


def render(
    system_prompt: str,
    user_input: str,
    style: str = "xml",
    allow_unsafe: bool = False,
) -> str:
    """
    Safely render a prompt with user input using clear boundaries.

    Args:
        system_prompt: The system prompt content
        user_input: User input to be rendered
        style: Rendering style ("xml" or "markdown")
        allow_unsafe: Skip sanitization if True

    Returns:
        Rendered prompt with safe user input boundaries
    """
    # Sanitize unless explicitly allowed
    if not allow_unsafe:
        user_input, is_safe = sanitize(user_input)
        if not is_safe:
            logger.warning("Unsafe patterns detected in user input during render")

    if style == "xml":
        return f"{system_prompt}\n\n<user_input>{user_input}</user_input>"
    elif style == "markdown":
        return f"{system_prompt}\n\n### USER INPUT\n{user_input}\n### END USER INPUT"
    else:
        from ..core.exceptions import ConfigurationError

        raise ConfigurationError(
            f"Unknown style: {style}",
            details={"style": style, "valid_styles": ["xml", "markdown"]},
        )


def calculate_risk_score(content: str) -> int:
    """
    Calculate risk score (0-100) based on dangerous patterns.

    Args:
        content: Content to analyze

    Returns:
        Risk score from 0 to 100
    """
    score = 0
    matches = 0

    for pattern in BLOCKLIST_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            matches += 1

    # Each match adds ~14 points
    score = min(matches * 14, 100)
    return score


def detect_pii(content: str, block: bool = False) -> List[str]:
    """
    Detect PII in content.

    Args:
        content: Content to scan
        block: Raise ComplianceError if PII found

    Returns:
        List of detected PII types

    Raises:
        ComplianceError: If block=True and PII found
    """
    from ..core.exceptions import ComplianceError

    detected = []

    for pii_type, pattern in PII_PATTERNS.items():
        if re.search(pattern, content):
            detected.append(pii_type)

    if block and detected:
        raise ComplianceError(
            f"PII detected: {', '.join(detected)}",
            details={"pii_types": detected},
        )

    return detected
