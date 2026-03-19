/**
 * Universal Prompt Security Standard (UPSS) - Core Engine
 * 
 * A runtime security framework for AI agents that prevents prompt injection,
 * jailbreaking, and other LLM-related attacks through a modular middleware architecture.
 */

// Core classes
export { SecurityContext, type SecurityContextData, type RiskLevel, type Environment } from "./core/context.js";
export { SecurityResult, type SecurityResultData, type SecurityIssue } from "./core/result.js";
export { SecurityMiddleware } from "./core/middleware.js";
export { SecurityPipeline } from "./core/pipeline.js";

// Exceptions
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

// Middleware
export { BasicSanitizer } from "./middleware/sanitizer.js";
export { InputValidator } from "./middleware/validator.js";
export { LightweightAuditor, type AuditEntry } from "./middleware/auditor.js";
export { SimpleRBAC, type Role, type Category, type RolesConfig } from "./middleware/rbac.js";

// Storage
export { FilesystemStorage, type PromptFile, type PromptsConfig } from "./storage/filesystem.js";
export { RulesLoader, type SecurityRule, type RulesConfig } from "./storage/rules.js";

// Scanner patterns
export {
  BLOCKLIST_PATTERNS,
  PII_PATTERNS,
  DEFAULT_INJECTION_PATTERNS,
  CONTROL_CHARS,
  SPECIAL_CHARS_ESCAPE,
} from "./scanner/patterns.js";

// Version
export const VERSION = "1.1.0";
