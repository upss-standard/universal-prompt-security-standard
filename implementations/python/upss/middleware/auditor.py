"""
Lightweight audit logging middleware with structured security events.

This module provides simple, file-based audit logging without requiring
complex infrastructure setup.

OWASP LLM01:2025 Control: RS-01 through RS-05, CR-03 - Audit Logging
"""

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.middleware import SecurityContext, SecurityMiddleware, SecurityResult


class LightweightAuditor(SecurityMiddleware):
    """
    Minimal audit logging middleware with structured security event logging.

    Logs all prompt access and security events to a JSONL (JSON Lines) file
    for audit trail. No complex infrastructure required - just file-based logging.

    Each log entry includes:
    - Timestamp (ISO 8601 format)
    - User ID
    - Prompt ID
    - Prompt hash (SHA-256 first 16 chars)
    - Risk level
    - Environment
    - Gate ID and Control ID (from previous middleware results)
    - Security status (passed/blocked)
    - Violations detected
    - Prompt length and preview

    Example:
        pipeline = SecurityPipeline()
        pipeline.use(BasicSanitizer())
        pipeline.use(InputValidator())
        pipeline.use(LightweightAuditor())  # Log results from all previous

        # Or with custom log path
        pipeline.use(LightweightAuditor(log_path="logs/custom_audit.jsonl"))
    """

    def __init__(self, log_path: str = "logs/upss_audit.jsonl"):
        """
        Initialize the auditor.

        Args:
            log_path: Path to the audit log file (JSONL format)
        """
        self.log_path = Path(log_path)

        # Create log directory if it doesn't exist
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        # Create log file if it doesn't exist
        if not self.log_path.exists():
            self.log_path.touch()

    def _compute_prompt_hash(self, prompt: str) -> str:
        """
        Compute SHA-256 hash of prompt for logging (first 16 chars).

        Args:
            prompt: The prompt text

        Returns:
            First 16 characters of SHA-256 hash
        """
        return hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:16]

    def _extract_gate_info(self, metadata: dict) -> dict:
        """
        Extract gate and control information from middleware metadata.

        Looks through all middleware results to find gate/control IDs.

        Args:
            metadata: Metadata dict from SecurityResult

        Returns:
            Dict with gate, control_id, and status info
        """
        gate_info: Dict[str, Any] = {
            "gates_passed": [],
            "gates_failed": [],
            "control_ids": [],
            "status": "passed",
        }

        # Check for middleware_results (from pipeline execution)
        middleware_results = metadata.get("middleware_results", {})

        for middleware_name, result_meta in middleware_results.items():
            gate = result_meta.get("gate", "")
            control_id = result_meta.get("control_id", "")
            status = result_meta.get("status", "")

            if gate:
                if status == "passed" or result_meta.get("violations", []) == []:
                    gate_info["gates_passed"].append(gate)
                else:
                    gate_info["gates_failed"].append(gate)
                    gate_info["status"] = "blocked"

            if control_id and control_id not in gate_info["control_ids"]:
                gate_info["control_ids"].append(control_id)

        return gate_info

    async def process(self, prompt: str, context: SecurityContext) -> SecurityResult:
        """
        Log prompt access and security events.

        Creates a structured audit entry with:
        - Gate ID and Control ID from previous middleware
        - Prompt hash for integrity tracking
        - Security status (passed/blocked)
        - All violations detected

        Args:
            prompt: The prompt text
            context: Security context (may contain middleware_results in metadata)

        Returns:
            SecurityResult marking prompt as safe (auditor doesn't block)
        """
        prompt_hash = self._compute_prompt_hash(prompt)
        metadata = context.metadata or {}

        # Extract gate information from previous middleware results
        gate_info = self._extract_gate_info(metadata)

        # Create audit entry with structured security event data
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "user_id": context.user_id,
            "prompt_id": context.prompt_id,
            "prompt_hash": prompt_hash,
            "risk_level": context.risk_level,
            "environment": context.environment,
            "prompt_length": len(prompt),
            "prompt_preview": prompt[:100] if len(prompt) > 100 else prompt,
            # Structured security fields
            "gates_passed": gate_info["gates_passed"],
            "gates_failed": gate_info["gates_failed"],
            "control_ids": gate_info["control_ids"],
            "status": gate_info["status"],
            "violations": metadata.get("violations", []),
            # Full metadata for debugging
            "metadata": metadata,
        }

        # Append to log file (JSONL format - one JSON object per line)
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(audit_entry) + "\n")

            logged = True
            error = None
        except Exception as e:
            logged = False
            error = str(e)

        # Auditor never blocks - always returns safe
        return SecurityResult(
            prompt=prompt,
            is_safe=True,
            risk_score=0.0,
            violations=[],
            metadata={
                "audited": logged,
                "log_path": str(self.log_path),
                "prompt_hash": prompt_hash,
                "error": error,
            },
        )

    def _matches_filters(
        self,
        entry: dict,
        user_id: Optional[str],
        prompt_id: Optional[str],
        prompt_hash: Optional[str],
        status: Optional[str],
        control_id: Optional[str],
        start_time: Optional[datetime],
        end_time: Optional[datetime],
    ) -> bool:
        """Check if entry matches all filters."""
        if user_id and entry.get("user_id") != user_id:
            return False

        if prompt_id and entry.get("prompt_id") != prompt_id:
            return False

        if prompt_hash and entry.get("prompt_hash") != prompt_hash:
            return False

        if status and entry.get("status") != status:
            return False

        if control_id and control_id not in entry.get("control_ids", []):
            return False

        if start_time or end_time:
            try:
                entry_time = datetime.fromisoformat(
                    entry["timestamp"].replace("Z", "+00:00")
                )
                if start_time and entry_time < start_time:
                    return False
                if end_time and entry_time > end_time:
                    return False
            except (KeyError, ValueError):
                return False

        return True

    def query_logs(
        self,
        user_id: Optional[str] = None,
        prompt_id: Optional[str] = None,
        prompt_hash: Optional[str] = None,
        status: Optional[str] = None,
        control_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[dict]:
        """
        Query audit logs with filters.

        Args:
            user_id: Filter by user ID
            prompt_id: Filter by prompt ID
            prompt_hash: Filter by prompt hash
            status: Filter by status (passed/blocked)
            control_id: Filter by control ID (RS-01, CR-03, etc.)
            start_time: Filter by start time
            end_time: Filter by end time
            limit: Maximum number of entries to return

        Returns:
            List of audit entries matching filters
        """
        if not self.log_path.exists():
            return []

        results: List[dict] = []

        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                if len(results) >= limit:
                    break

                try:
                    entry = json.loads(line.strip())
                    if self._matches_filters(
                        entry,
                        user_id,
                        prompt_id,
                        prompt_hash,
                        status,
                        control_id,
                        start_time,
                        end_time,
                    ):
                        results.append(entry)
                except json.JSONDecodeError:
                    # Skip malformed entries
                    continue

        return results

    def get_security_summary(self) -> dict:
        """
        Get summary of security events from logs.

        Returns:
            Dict with counts of passed/blocked, control_ids hit, etc.
        """
        if not self.log_path.exists():
            return {"total": 0, "passed": 0, "blocked": 0, "control_ids": {}}

        total = 0
        passed = 0
        blocked = 0
        control_id_counts: dict = {}

        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    total += 1

                    if entry.get("status") == "passed":
                        passed += 1
                    elif entry.get("status") == "blocked":
                        blocked += 1

                    for cid in entry.get("control_ids", []):
                        control_id_counts[cid] = control_id_counts.get(cid, 0) + 1
                except json.JSONDecodeError:
                    continue

        return {
            "total": total,
            "passed": passed,
            "blocked": blocked,
            "control_ids": control_id_counts,
        }
