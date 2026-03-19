"""
Rate limiting middleware (Gate 6 - RS-05).

This module provides SQLite-backed rate limiting to prevent abuse
and brute-force attacks.

OWASP LLM01:2025 Control: RS-05 - Rate Limiting
"""

import logging
import sqlite3
import time
from pathlib import Path
from typing import Dict, Optional

from ..core.middleware import SecurityContext, SecurityMiddleware, SecurityResult

logger = logging.getLogger(__name__)


class RateLimitMiddleware(SecurityMiddleware):
    """
    Rate limiting middleware with SQLite backend.

    Enforces per-user request rate limits to prevent abuse. This is Gate 6
    in the UPSS security chain (RS-05).

    Uses a sliding window algorithm with SQLite for persistence across
    restarts and concurrent processes.

    Default limits by role:
    - user: 60 requests/minute
    - developer: 100 requests/minute
    - admin: 1000 requests/minute

    Example:
        pipeline = SecurityPipeline()
        pipeline.use(RateLimitMiddleware(db_path="~/.upss/upss.db"))

        # With custom limits
        pipeline.use(RateLimitMiddleware(
            db_path="~/.upss/upss.db",
            limits={
                "user": 30,
                "developer": 60,
                "admin": 500,
            }
        ))

    Attributes:
        db_path: Path to SQLite database
        limits: Mapping of role to requests-per-minute limit
        window_seconds: Time window for rate limiting (default: 60)
    """

    DEFAULT_LIMITS = {
        "user": 60,
        "developer": 100,
        "admin": 1000,
    }

    def __init__(
        self,
        db_path: str = "~/.upss/upss.db",
        limits: Optional[Dict[str, int]] = None,
        window_seconds: int = 60,
    ):
        """
        Initialize rate limit middleware.

        Args:
            db_path: Path to SQLite database for rate limit state
            limits: Custom limits per role (requests per minute)
            window_seconds: Time window for rate limiting (default: 60)
        """
        self.db_path = Path(db_path).expanduser()
        self.limits = {**self.DEFAULT_LIMITS, **(limits or {})}
        self.window_seconds = window_seconds

        # Initialize database
        self._init_db()

    def _init_db(self) -> None:
        """Initialize SQLite database with required tables."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS rate_limits (
                    user_id TEXT NOT NULL,
                    window_start REAL NOT NULL,
                    request_count INTEGER DEFAULT 1,
                    PRIMARY KEY (user_id, window_start)
                )
            """)
            conn.commit()

        logger.info(f"Rate limit database initialized at {self.db_path}")

    def _get_user_role(self, context: SecurityContext) -> str:
        """
        Get user role from context metadata.

        Args:
            context: Security context with metadata

        Returns:
            Role string (default: "user")
        """
        metadata = context.metadata or {}
        return metadata.get("role", "user")

    def _get_limit_for_role(self, role: str) -> int:
        """
        Get request limit for a role.

        Args:
            role: Role name

        Returns:
            Requests-per-minute limit
        """
        return self.limits.get(role, self.limits["user"])

    def _get_current_window(self) -> float:
        """Get current time window start timestamp."""
        current_time = time.time()
        return current_time - (current_time % self.window_seconds)

    def _increment_count(self, user_id: str) -> int:
        """
        Increment request count for user in current window.

        Uses SQLite transaction for atomicity.

        Args:
            user_id: User identifier

        Returns:
            Current request count in window
        """
        window_start = self._get_current_window()

        with sqlite3.connect(self.db_path) as conn:
            # Try to insert new row
            try:
                conn.execute(
                    """
                    INSERT INTO rate_limits (user_id, window_start, request_count)
                    VALUES (?, ?, 1)
                    """,
                    (user_id, window_start),
                )
                count = 1
            except sqlite3.IntegrityError:
                # Row exists, increment count
                cursor = conn.execute(
                    """
                    UPDATE rate_limits
                    SET request_count = request_count + 1
                    WHERE user_id = ? AND window_start = ?
                    """,
                    (user_id, window_start),
                )
                if cursor.rowcount > 0:
                    cursor = conn.execute(
                        """
                        SELECT request_count FROM rate_limits
                        WHERE user_id = ? AND window_start = ?
                        """,
                        (user_id, window_start),
                    )
                    row = cursor.fetchone()
                    count = row[0] if row else 1
                else:
                    count = 1

            # Clean up old windows (keep last 5 minutes of data)
            cutoff = time.time() - (5 * 60)
            conn.execute(
                "DELETE FROM rate_limits WHERE window_start < ?",
                (cutoff,),
            )

            conn.commit()

        return count

    def _get_current_count(self, user_id: str) -> int:
        """
        Get current request count for user without incrementing.

        Args:
            user_id: User identifier

        Returns:
            Current request count in window
        """
        window_start = self._get_current_window()

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                SELECT request_count FROM rate_limits
                WHERE user_id = ? AND window_start = ?
                """,
                (user_id, window_start),
            )
            row = cursor.fetchone()
            return row[0] if row else 0

    async def process(self, prompt: str, context: SecurityContext) -> SecurityResult:
        """
        Check and enforce rate limits.

        Gate 6 (RS-05) - Rate Limit Check:
        1. Get user role from context metadata
        2. Determine requests-per-minute limit for role
        3. Increment request count for current window
        4. If limit exceeded → BLOCK temporarily
        5. Log security event

        Args:
            prompt: The prompt text
            context: Security context (user_id, role in metadata)

        Returns:
            SecurityResult indicating whether request is allowed
        """
        user_id = context.user_id
        role = self._get_user_role(context)
        limit = self._get_limit_for_role(role)

        # Increment and get current count
        current_count = self._increment_count(user_id)

        if current_count > limit:
            # Rate limit exceeded
            logger.warning(
                f"RS-05: Rate limit exceeded for user_id={user_id} "
                f"role={role} count={current_count} limit={limit}"
            )
            return SecurityResult(
                prompt=prompt,
                is_safe=False,
                risk_score=0.7,
                violations=[
                    f"RS-05: Rate limit exceeded for user {user_id} "
                    f"({current_count}/{limit} requests in last {self.window_seconds}s)"
                ],
                metadata={
                    "gate": "Gate 6",
                    "control_id": "RS-05",
                    "user_id": user_id,
                    "role": role,
                    "current_count": current_count,
                    "limit": limit,
                    "window_seconds": self.window_seconds,
                    "status": "rate_limited",
                },
            )

        # Request allowed
        logger.debug(
            f"RS-05: Rate check passed for user_id={user_id} "
            f"role={role} count={current_count}/{limit}"
        )
        return SecurityResult(
            prompt=prompt,
            is_safe=True,
            risk_score=0.0,
            violations=[],
            metadata={
                "gate": "Gate 6",
                "control_id": "RS-05",
                "user_id": user_id,
                "role": role,
                "current_count": current_count,
                "limit": limit,
                "window_seconds": self.window_seconds,
                "status": "passed",
            },
        )

    def reset_user(self, user_id: str) -> None:
        """
        Reset rate limit state for a user.

        Args:
            user_id: User identifier to reset
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "DELETE FROM rate_limits WHERE user_id = ?",
                (user_id,),
            )
            conn.commit()

        logger.info(f"Rate limit reset for user_id={user_id}")

    def get_user_status(self, user_id: str) -> Dict[str, int]:
        """
        Get rate limit status for a user.

        Args:
            user_id: User identifier

        Returns:
            Dict with current_count, limit, remaining
        """
        current_count = self._get_current_count(user_id)
        # Default role for status check
        limit = self.limits["user"]

        return {
            "current_count": current_count,
            "limit": limit,
            "remaining": max(0, limit - current_count),
        }