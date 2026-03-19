"""
Basic sanitization middleware for prompt injection prevention.

This module provides essential prompt sanitization to block common
injection patterns with minimal overhead.
"""

import re
from typing import List, Optional, Pattern

from ..core.middleware import SecurityContext, SecurityMiddleware, SecurityResult


class BasicSanitizer(SecurityMiddleware):
    """
    Essential prompt sanitization middleware.

    Blocks common prompt injection patterns with minimal configuration.
    This should be the first middleware in most security pipelines.

    Default patterns blocked:
    - Instruction override attempts (ignore previous, disregard above)
    - Role confusion (you are now, act as if)
    - System prompt injection (system:, <|im_start|>)
    - Delimiter injection attempts

    Example:
        pipeline = SecurityPipeline()
        pipeline.use(BasicSanitizer())

        # Or with custom patterns
        pipeline.use(BasicSanitizer(
            block_patterns=[
                r"custom_pattern_1",
                r"custom_pattern_2"
            ]
        ))
    """

    # Default injection patterns to block
    DEFAULT_PATTERNS = [
        # Instruction override
        r"ignore\s+(previous|above|prior)\s+(instructions?|prompts?|commands?)",
        r"disregard\s+(previous|above|all|everything)",
        r"forget\s+(previous|above|all|everything)",
        # Role confusion
        r"you\s+are\s+now",
        r"act\s+as\s+if",
        r"pretend\s+(to\s+be|you\s+are)",
        r"simulate\s+(being|that\s+you)",
        # System prompt injection
        r"new\s+instructions?:",
        r"system\s*:\s*",
        r"<\s*\|\s*im_start\s*\|\s*>",
        r"<\s*\|\s*im_end\s*\|\s*>",
        # Delimiter injection
        r"---\s*end\s+of\s+prompt",
        r"```\s*system",
        # Privilege escalation
        r"sudo\s+mode",
        r"admin\s+mode",
        r"developer\s+mode",
        r"god\s+mode",
        r"root\s+access",
        # Jailbreak attempts
        r"jailbreak",
        r"DAN\b",
        # System prompt extraction
        r"reveal\s+your\s+(system\s+)?prompt",
        r"show\s+me\s+your\s+(system\s+)?(prompt|instructions)",
        r"what\s+is\s+your\s+system\s+prompt",
        r"repeat\s+(your\s+)?(system\s+)?instructions",
    ]

    def __init__(self, block_patterns: Optional[List[str]] = None):
        """
        Initialize the sanitizer.

        Args:
            block_patterns: Custom patterns to block (replaces defaults if provided)
        """
        patterns = (
            block_patterns if block_patterns is not None else self.DEFAULT_PATTERNS
        )
        self.patterns: List[Pattern] = [
            re.compile(pattern, re.IGNORECASE) for pattern in patterns
        ]

    async def process(self, prompt: str, context: SecurityContext) -> SecurityResult:
        """
        Scan prompt for injection patterns and sanitize if needed.

        Args:
            prompt: The prompt text to sanitize
            context: Security context

        Returns:
            SecurityResult with sanitized prompt and any violations detected
        """
        violations: List[str] = []
        cleaned_prompt = prompt
        matches_found = 0

        for pattern in self.patterns:
            matches = list(pattern.finditer(prompt))

            for match in matches:
                matches_found += 1
                matched_text = match.group()

                violations.append(f"Injection pattern detected: '{matched_text}'")

                # Redact the matched pattern
                cleaned_prompt = cleaned_prompt.replace(matched_text, "[REDACTED]")

        # Calculate risk score based on number of violations
        # Each violation adds 0.3 to risk score, capped at 1.0
        risk_score = min(len(violations) * 0.3, 1.0)

        return SecurityResult(
            prompt=cleaned_prompt,
            is_safe=len(violations) == 0,
            risk_score=risk_score,
            violations=violations,
            metadata={
                "patterns_checked": len(self.patterns),
                "matches_found": matches_found,
                "sanitized": len(violations) > 0,
            },
        )
