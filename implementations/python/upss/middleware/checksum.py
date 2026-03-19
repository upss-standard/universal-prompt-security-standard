"""
Checksum integrity verification middleware (Gate 5 - CR-03).

This module provides SHA-256 checksum verification for prompt artifacts
to detect supply-chain tampering.

OWASP LLM01:2025 Control: CR-03 - Cryptographic Integrity Verification
"""

import hashlib
import logging
from pathlib import Path
from typing import Dict, Optional

from ..core.exceptions import IntegrityError
from ..core.middleware import SecurityContext, SecurityMiddleware, SecurityResult

logger = logging.getLogger(__name__)


class ChecksumMiddleware(SecurityMiddleware):
    """
    Checksum integrity verification middleware.

    Verifies SHA-256 checksums of prompt artifacts to detect supply-chain
    tampering. This is Gate 5 in the UPSS security chain (CR-03).

    The middleware maintains a registry of known checksums and validates
    prompt content against stored values. If a checksum doesn't match,
    the prompt is blocked immediately.

    Example:
        pipeline = SecurityPipeline()
        pipeline.use(ChecksumMiddleware(checksums_path="~/.upss/checksums.json"))

        # Or with inline checksums
        pipeline.use(ChecksumMiddleware(checksums={
            "system_prompt": "a1b2c3...",
            "assistant_prompt": "d4e5f6..."
        }))

    Attributes:
        checksums: Mapping of prompt_id to expected SHA-256 checksum
        fail_on_missing: Whether to block prompts without registered checksums
    """

    def __init__(
        self,
        checksums: Optional[Dict[str, str]] = None,
        checksums_path: Optional[str] = None,
        fail_on_missing: bool = False,
    ):
        """
        Initialize checksum middleware.

        Args:
            checksums: Direct mapping of prompt_id to SHA-256 checksum
            checksums_path: Path to JSON file containing checksums
            fail_on_missing: If True, block prompts without checksums (default: warn only)
        """
        self.checksums: Dict[str, str] = {}
        self.fail_on_missing = fail_on_missing

        # Load checksums from direct parameter
        if checksums:
            self.checksums.update(checksums)

        # Load checksums from file if provided
        if checksums_path:
            self._load_checksums_file(checksums_path)

    def _load_checksums_file(self, path: str) -> None:
        """Load checksums from JSON file."""
        import json

        checksum_path = Path(path).expanduser()
        if checksum_path.exists():
            try:
                with open(checksum_path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                    self.checksums.update(loaded)
                logger.info(f"Loaded {len(loaded)} checksums from {checksum_path}")
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to load checksums from {checksum_path}: {e}")
        else:
            logger.info(f"Checksum file not found: {checksum_path}")

    def _compute_checksum(self, content: str) -> str:
        """
        Compute SHA-256 checksum of content.

        Args:
            content: The content to hash

        Returns:
            Hexadecimal SHA-256 digest
        """
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def _compute_prompt_hash(self, prompt: str) -> str:
        """
        Compute short hash for logging (first 16 chars of SHA-256).

        Args:
            prompt: The prompt text

        Returns:
            First 16 characters of SHA-256 hash
        """
        return self._compute_checksum(prompt)[:16]

    def register_checksum(self, prompt_id: str, content: str) -> str:
        """
        Register a new checksum for a prompt.

        Args:
            prompt_id: Identifier for the prompt
            content: The prompt content to hash

        Returns:
            The computed SHA-256 checksum
        """
        checksum = self._compute_checksum(content)
        self.checksums[prompt_id] = checksum
        logger.info(f"Registered checksum for {prompt_id}: {checksum[:16]}...")
        return checksum

    async def process(self, prompt: str, context: SecurityContext) -> SecurityResult:
        """
        Verify prompt checksum against registered value.

        Gate 5 (CR-03) - Checksum Integrity Verification:
        1. Check if prompt_id has a registered checksum
        2. Compute SHA-256 of prompt content
        3. Compare against stored checksum
        4. BLOCK on mismatch (possible tampering)
        5. WARN if no checksum registered (unless fail_on_missing=True)

        Args:
            prompt: The prompt text to verify
            context: Security context (uses prompt_id to lookup checksum)

        Returns:
            SecurityResult indicating whether checksum verified
        """
        prompt_id = context.prompt_id
        prompt_hash = self._compute_prompt_hash(prompt)

        # Check if this prompt has a registered checksum
        if prompt_id not in self.checksums:
            if self.fail_on_missing:
                logger.warning(
                    f"CR-03: No checksum registered for prompt_id={prompt_id} "
                    f"(prompt_hash={prompt_hash})"
                )
                return SecurityResult(
                    prompt=prompt,
                    is_safe=False,
                    risk_score=0.5,
                    violations=[
                        f"CR-03: No checksum registered for prompt '{prompt_id}' "
                        "- prompt artifact not UPSS-compliant"
                    ],
                    metadata={
                        "gate": "Gate 5",
                        "control_id": "CR-03",
                        "prompt_id": prompt_id,
                        "prompt_hash": prompt_hash,
                        "status": "missing_checksum",
                    },
                )
            else:
                # Warn but allow (soft failure)
                logger.info(
                    f"CR-03: No checksum registered for prompt_id={prompt_id} "
                    f"(prompt_hash={prompt_hash}) - allowing with warning"
                )
                return SecurityResult(
                    prompt=prompt,
                    is_safe=True,
                    risk_score=0.1,
                    violations=[],
                    metadata={
                        "gate": "Gate 5",
                        "control_id": "CR-03",
                        "prompt_id": prompt_id,
                        "prompt_hash": prompt_hash,
                        "status": "no_checksum_warning",
                    },
                )

        # Compute and compare checksum
        expected = self.checksums[prompt_id]
        actual = self._compute_checksum(prompt)

        if actual != expected:
            # CRITICAL: Checksum mismatch - possible supply-chain tampering
            logger.error(
                f"CR-03: CHECKSUM MISMATCH for prompt_id={prompt_id} "
                f"expected={expected[:16]}... actual={actual[:16]}... "
                f"- POSSIBLE SUPPLY-CHAIN TAMPERING"
            )
            return SecurityResult(
                prompt=prompt,
                is_safe=False,
                risk_score=1.0,
                violations=[
                    f"CR-03: Checksum mismatch on '{prompt_id}' - "
                    "possible supply-chain tampering detected"
                ],
                metadata={
                    "gate": "Gate 5",
                    "control_id": "CR-03",
                    "prompt_id": prompt_id,
                    "prompt_hash": prompt_hash,
                    "expected_checksum": expected[:16] + "...",
                    "actual_checksum": actual[:16] + "...",
                    "status": "checksum_mismatch",
                },
            )

        # Checksum verified successfully
        logger.info(
            f"CR-03: Checksum verified for prompt_id={prompt_id} "
            f"(prompt_hash={prompt_hash})"
        )
        return SecurityResult(
            prompt=prompt,
            is_safe=True,
            risk_score=0.0,
            violations=[],
            metadata={
                "gate": "Gate 5",
                "control_id": "CR-03",
                "prompt_id": prompt_id,
                "prompt_hash": prompt_hash,
                "checksum": actual[:16] + "...",
                "status": "verified",
            },
        )

    def save_checksums(self, path: str) -> None:
        """
        Save current checksums to JSON file.

        Args:
            path: Path to save checksums
        """
        import json

        checksum_path = Path(path).expanduser()
        checksum_path.parent.mkdir(parents=True, exist_ok=True)

        with open(checksum_path, "w", encoding="utf-8") as f:
            json.dump(self.checksums, f, indent=2)

        logger.info(f"Saved {len(self.checksums)} checksums to {checksum_path}")