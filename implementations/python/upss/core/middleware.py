"""
Base middleware classes for UPSS v1.1.0 modular security architecture.

This module provides the foundation for composable security primitives that can be
mixed and matched to create custom security pipelines.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class SecurityContext:
    """
    Context information for security operations.

    Attributes:
        user_id: Identifier for the user making the request
        prompt_id: Identifier for the prompt being accessed
        risk_level: Risk level (low, medium, high)
        environment: Deployment environment (development, staging, production)
        metadata: Additional context-specific metadata
    """

    user_id: str
    prompt_id: str
    risk_level: str = "medium"
    environment: str = "production"
    metadata: Optional[Dict[str, Any]] = None

    def __post_init__(self) -> None:
        if self.metadata is None:
            self.metadata = {}

        # Validate risk level
        valid_levels = {"low", "medium", "high"}
        if self.risk_level not in valid_levels:
            from .exceptions import ConfigurationError
            raise ConfigurationError(
                f"Invalid risk_level: {self.risk_level}. Must be one of {valid_levels}",
                details={"risk_level": self.risk_level, "valid_levels": list(valid_levels)}
            )

@dataclass
class SecurityResult:
    """
    Result of security middleware processing.

    Attributes:
        prompt: The processed prompt (may be modified by middleware)
        is_safe: Whether the prompt passed all security checks
        risk_score: Numerical risk score (0.0 = safe, 1.0 = maximum risk)
        violations: List of security violations detected
        metadata: Additional result metadata from middleware
    """

    prompt: str
    is_safe: bool
    risk_score: float
    violations: List[str]
    metadata: Dict[str, Any]

    def __post_init__(self) -> None:
        # Ensure risk_score is in valid range
        if not 0.0 <= self.risk_score <= 1.0:
            from .exceptions import ConfigurationError
            raise ConfigurationError(
                f"risk_score must be between 0.0 and 1.0, got {self.risk_score}",
                details={"risk_score": self.risk_score}
            )
class SecurityMiddleware(ABC):
    """
    Abstract base class for all security middleware.

    Security middleware processes prompts through a specific security check
    and returns a result indicating whether the prompt is safe to use.

    Middleware can:
    - Validate prompt content
    - Modify prompts (sanitization, redaction)
    - Log access for audit
    - Enforce policies
    - Detect anomalies

    Example:
        class MyMiddleware(SecurityMiddleware):
            async def process(
                self, prompt: str, context: SecurityContext
            ) -> SecurityResult:
                # Perform security check
                if "unsafe_pattern" in prompt:
                    return SecurityResult(
                        prompt=prompt,
                        is_safe=False,
                        risk_score=0.8,
                        violations=["Unsafe pattern detected"],
                        metadata={"check": "pattern_match"}
                    )

                return SecurityResult(
                    prompt=prompt,
                    is_safe=True,
                    risk_score=0.0,
                    violations=[],
                    metadata={"check": "passed"}
                )
    """

    @abstractmethod
    async def process(self, prompt: str, context: SecurityContext) -> SecurityResult:
        """
        Process a prompt through this security middleware.

        Args:
            prompt: The prompt text to process
            context: Security context for the operation

        Returns:
            SecurityResult indicating whether the prompt is safe

        Raises:
            SecurityError: If a critical security issue is detected
        """
        pass

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}()"


class SecurityPipeline:
    """
    Composable security middleware pipeline.

    The pipeline executes middleware in sequence, allowing each to validate
    and potentially modify the prompt. If any middleware marks the prompt as
    unsafe, the pipeline stops execution.

    Example:
        pipeline = SecurityPipeline()
        pipeline.use(BasicSanitizer())
        pipeline.use(LightweightAuditor())
        pipeline.use(SimpleRBAC())

        context = SecurityContext(user_id="alice", prompt_id="greeting")
        result = await pipeline.execute(user_prompt, context)

        if result.is_safe:
            # Use the secure prompt
            response = await llm.generate(result.prompt)
        else:
            # Handle security violations
            log_security_event(result.violations)
    """

    def __init__(self) -> None:
        """Initialize an empty security pipeline."""
        self.middlewares: List[SecurityMiddleware] = []

    def use(self, middleware: SecurityMiddleware) -> "SecurityPipeline":
        """
        Add middleware to the pipeline.

        Middleware is executed in the order it is added.

        Args:
            middleware: SecurityMiddleware instance to add

        Returns:
            Self for method chaining (fluent interface)

        Example:
            pipeline = SecurityPipeline()
            pipeline.use(BasicSanitizer()).use(LightweightAuditor())
        """
        self.middlewares.append(middleware)
        return self

    async def execute(self, prompt: str, context: SecurityContext) -> SecurityResult:
        """
        Execute all middleware in the pipeline.

        Middleware is executed sequentially. If any middleware marks the prompt
        as unsafe, execution stops and the result is returned immediately.

        Args:
            prompt: The prompt text to process
            context: Security context for the operation

        Returns:
            SecurityResult with aggregated results from all middleware

        Example:
            result = await pipeline.execute(
                "Summarize this document",
                SecurityContext(user_id="alice", prompt_id="summarize")
            )
        """
        if not self.middlewares:
            # No middleware configured, return safe result
            return SecurityResult(
                prompt=prompt,
                is_safe=True,
                risk_score=0.0,
                violations=[],
                metadata={"middleware_count": 0},
            )

        current_prompt = prompt
        all_violations: List[str] = []
        max_risk_score = 0.0
        all_metadata: Dict[str, Any] = {}

        for middleware in self.middlewares:
            result = await middleware.process(current_prompt, context)

            # Update prompt (middleware may have modified it)
            current_prompt = result.prompt

            # Aggregate violations
            all_violations.extend(result.violations)

            # Track maximum risk score
            max_risk_score = max(max_risk_score, result.risk_score)

            # Merge metadata
            middleware_name = middleware.__class__.__name__
            all_metadata[middleware_name] = result.metadata

            # Stop if middleware marked prompt as unsafe
            if not result.is_safe:
                break

        return SecurityResult(
            prompt=current_prompt,
            is_safe=len(all_violations) == 0,
            risk_score=max_risk_score,
            violations=all_violations,
            metadata={
                "middleware_count": len(self.middlewares),
                "middleware_results": all_metadata,
            },
        )

    def __repr__(self) -> str:
        middleware_names = [m.__class__.__name__ for m in self.middlewares]
        return f"SecurityPipeline(middlewares={middleware_names})"
