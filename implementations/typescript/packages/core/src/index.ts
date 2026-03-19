/**
 * Universal Prompt Security Standard (UPSS) - TypeScript Implementation
 * 
 * A secure, production-ready library for managing LLM prompts following the UPSS
 * framework.
 * 
 * Version 1.1.0 introduces a modular middleware architecture for composable security.
 */

export { version } from "./version.js";

// Core models
export {
  SecurityContext,
  type SecurityContextParams,
  SecurityResult,
  type PromptContent,
  type AuditEntry,
  type MigrationReport,
  type RiskLevel,
  type Environment,
} from "./core/models.js";

// Core exceptions
export {
  UPSSError,
  ConfigurationError,
  StorageError,
  IntegrityError,
  PermissionError,
  NotFoundError,
  ConflictError,
  ComplianceError,
  SecurityError,
} from "./core/exceptions.js";

// Middleware architecture
export { SecurityMiddleware, SecurityPipeline } from "./core/middleware.js";

// Security middleware
export { BasicSanitizer } from "./middleware/sanitizer.js";
export { InputValidator } from "./middleware/validator.js";
export { SimpleRBAC, type RolesConfig } from "./middleware/rbac.js";
export { ChecksumMiddleware } from "./middleware/checksum.js";
export { RateLimitMiddleware } from "./middleware/ratelimit.js";

// Security utilities
export {
  sanitize,
  render,
  calculateRiskScore,
  detectPii,
  computeChecksum,
  verifyChecksum,
  BLOCKLIST_PATTERNS,
  PII_PATTERNS,
} from "./security/scanner.js";

// 6-Gate Pipeline
export {
  createSixGatePipeline,
  executeSixGates,
  formatGateResult,
  type SixGatePipelineConfig,
  type SixGateResult,
} from "./security/six-gate-pipeline.js";

// Re-export for convenience
export type { SecurityContextParams as ContextParams } from "./core/models.js";